use futures::future::join_all;
use iced_x86::{Decoder, DecoderOptions, FlowControl};
use patternsleuth::resolvers::{ResolveError, Result};
use patternsleuth::scanner::Pattern;
use std::{collections::HashSet, sync::Arc};

mod pipeline;
pub use pipeline::{ForkOutput, Matcher};
mod context;
pub use context::WithContext;
mod evaluation;
pub use evaluation::MatchContext;
mod cardinality;
mod disassembly;
pub use cardinality::{Cardinality, ExactlyOne, Variable};
pub use disassembly::Control;

#[cfg(test)]
mod tests;

/// Address-producing source matcher. Existing fluent address APIs remain available.
/// Construction, callbacks, and resolution use resolvers::Result and ResolveError.
pub type BinaryMatcher<'scope> = Matcher<'scope, (), u64>;

/// A parsed pattern or signature string accepted by BinaryMatcher::patterns.
pub trait IntoPattern {
    fn into_pattern(self) -> Result<Pattern>;
}

impl IntoPattern for Pattern {
    fn into_pattern(self) -> Result<Pattern> {
        Ok(self)
    }
}

impl IntoPattern for &Pattern {
    fn into_pattern(self) -> Result<Pattern> {
        Ok(self.clone())
    }
}

impl IntoPattern for &str {
    fn into_pattern(self) -> Result<Pattern> {
        parse_signature(self)
    }
}

impl IntoPattern for String {
    fn into_pattern(self) -> Result<Pattern> {
        parse_signature(self)
    }
}

impl IntoPattern for &String {
    fn into_pattern(self) -> Result<Pattern> {
        parse_signature(self)
    }
}

impl IntoPattern for &&str {
    fn into_pattern(self) -> Result<Pattern> {
        parse_signature(self)
    }
}

fn parse_signature(signature: impl AsRef<str>) -> Result<Pattern> {
    Pattern::new(signature).map_err(|error| ResolveError::new_msg(format!("{error:#}")))
}

/// A known address, not necessarily a function entry or instruction site.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

/// An instruction's address.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstructionSite(pub u64);

/// A root function's metadata. The end address is exclusive.
/// Bounds describe the root's recorded range, not any separate chained fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionEntry {
    pub start: u64,
    pub end: u64,
    /// Unwind-info address when supplied by the image backend.
    pub unwind: Option<u64>,
}

impl FunctionEntry {
    /// Byte length of the recorded range, not a count of decoded instructions.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}

/// A direct near-call instruction and its destination. Targets are not normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Call {
    pub site: InstructionSite,
    pub target: Address,
}

pub trait HasAddress {
    fn address(&self) -> u64;
}

impl HasAddress for u64 {
    fn address(&self) -> u64 {
        *self
    }
}

impl HasAddress for Address {
    fn address(&self) -> u64 {
        self.0
    }
}

impl HasAddress for InstructionSite {
    fn address(&self) -> u64 {
        self.0
    }
}

impl HasAddress for FunctionEntry {
    fn address(&self) -> u64 {
        self.start
    }
}

impl<'scope> BinaryMatcher<'scope> {
    pub fn pattern(pattern: Pattern) -> Self {
        Self::scan_patterns(vec![pattern])
    }

    /// Parse strings or accept existing patterns, failing immediately on invalid signatures.
    /// Accepts owned/borrowed Pattern and String values, &str, and borrowed &str collections.
    /// Submit scans together on resolution, retaining pattern order and duplicates.
    /// Errors identify the failing pattern's zero-based index; empty collections are valid.
    ///
    /// ```
    /// use binary_bloodhound::BinaryMatcher;
    /// use patternsleuth::resolvers::{Result, unreal::util};
    /// # fn example() -> Result<()> {
    /// let matcher = BinaryMatcher::patterns(["48 89 ?? ??", "E8 | ?? ?? ?? ??"])?;
    /// let signatures = ["AA BB CC", "AA ?? CC"];
    /// let borrowed = BinaryMatcher::patterns(&signatures)?;
    /// let parsed = [util::utf16_pattern("foo\0")];
    /// let from_patterns = BinaryMatcher::patterns(&parsed)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn patterns<P: IntoPattern>(patterns: impl IntoIterator<Item = P>) -> Result<Self> {
        let patterns = patterns
            .into_iter()
            .enumerate()
            .map(|(index, pattern)| {
                pattern.into_pattern().map_err(|error| {
                    ResolveError::new_msg(format!("invalid pattern at index {index}: {error}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::scan_patterns(patterns))
    }

    fn scan_patterns(patterns: Vec<Pattern>) -> Self {
        let patterns = Arc::new(patterns);
        Self::from_async(move |(), ctx| {
            let patterns = Arc::clone(&patterns);
            Box::pin(async move {
                let results =
                    join_all(patterns.iter().map(|pattern| ctx.scan(pattern.clone()))).await;
                Ok(results.into_iter().flatten().collect())
            })
        })
    }

    /// Return an address without checking image bounds.
    pub fn address(address: u64) -> Self {
        Self::candidates([address])
    }

    /// Produce supplied addresses without scanning or checking image bounds.
    /// Accepts arrays, slices and vectors of u64.
    /// Copies inputs at construction; resolution preserves order and duplicates.
    /// Empty input is valid. Cardinality is Variable, even for a singleton.
    ///
    /// ```
    /// use binary_bloodhound::BinaryMatcher;
    /// let array = BinaryMatcher::candidates([0x1000, 0x2000, 0x1000]);
    /// let slice = BinaryMatcher::candidates(&[0x1000_u64, 0x2000][..]);
    /// let vector = BinaryMatcher::candidates(vec![0x1000, 0x2000]);
    /// let expanded = BinaryMatcher::address(0x1000).flat_map(|address| {
    ///     BinaryMatcher::candidates([address, address + 4])
    /// });
    /// ```
    pub fn candidates(addresses: impl AsRef<[u64]>) -> Self {
        let addresses = addresses.as_ref().to_vec();
        Self::from_sync(move |()| Ok(addresses.clone()))
    }
}

impl<'scope, I: Send + 'scope, C: Cardinality> Matcher<'scope, I, FunctionEntry, C> {
    /// Collect reachable instructions into one vector per function, retaining cardinality.
    /// Visit fallthrough before queued branches (LIFO), without following calls.
    /// Function ranges intersect search bounds; out-of-range branches are skipped.
    /// Empty ranges produce empty vectors. Memory and invalid-instruction errors propagate.
    ///
    /// ```
    /// use binary_bloodhound::BinaryMatcher;
    /// let matcher = BinaryMatcher::address(0x1000)
    ///     .root_functions()
    ///     .disassemble()
    ///     .map_filter(|instructions| {
    ///         instructions.into_iter().find(|instruction| instruction.is_call_near())
    ///     });
    /// ```
    ///
    /// Function metadata is required; raw addresses do not define decoding bounds:
    /// ```compile_fail
    /// use binary_bloodhound::BinaryMatcher;
    /// let invalid = BinaryMatcher::address(0x1000).disassemble();
    /// ```
    pub fn disassemble(self) -> Matcher<'scope, I, Vec<iced_x86::Instruction>, C> {
        self.disassemble_until(|_| false)
    }

    /// Like disassemble, but stop the current path after including an instruction
    /// matching the predicate. Previously queued branches still run.
    /// The stopped instruction's branch target is not followed or queued.
    pub fn disassemble_until<F>(self, stop: F) -> Matcher<'scope, I, Vec<iced_x86::Instruction>, C>
    where
        F: Fn(&iced_x86::Instruction) -> bool + Send + Sync + 'scope,
    {
        self.with_context()
            .try_map(move |(ctx, function)| disassembly::collect(ctx, function, &stop))
    }

    /// Run an inner matcher within each function's half-open range, in input order.
    /// Concatenate results without deduplication. Nested scopes intersect their bounds;
    /// empty scopes are skipped, invalid ranges and inner errors stop evaluation.
    /// Memory reads and returned targets may lie outside the function.
    ///
    /// ```
    /// use binary_bloodhound::BinaryMatcher;
    /// # fn example() -> patternsleuth::resolvers::Result<()> {
    /// let calls = BinaryMatcher::patterns(["40 53 48 83 EC ??"])?
    ///     .root_functions()
    ///     .sub(BinaryMatcher::patterns(["E8 | ?? ?? ?? ??"])?.rip4());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Raw addresses do not provide function bounds:
    /// ```compile_fail
    /// use binary_bloodhound::BinaryMatcher;
    /// let invalid = BinaryMatcher::address(0x1000).sub(BinaryMatcher::address(0x2000));
    /// ```
    #[allow(clippy::should_implement_trait)] // Function-scoped search, not subtraction.
    pub fn sub<T: Send + 'scope, D: Cardinality>(
        self,
        matcher: Matcher<'scope, (), T, D>,
    ) -> Matcher<'scope, I, T> {
        Matcher::from_run(pipeline::Sub {
            functions: self,
            matcher,
        })
    }
}

impl<'scope, I: Send + 'scope, T: HasAddress + Send + 'scope, C: Cardinality>
    Matcher<'scope, I, T, C>
{
    /// Fold instructions from each candidate's containing root using upstream traversal.
    /// Resolve function metadata from the image; skip unknown roots without initializing.
    /// Initialize state from the original candidate, not the resolved function metadata.
    /// Clone state at queued branches; only Control::Return emits a candidate.
    /// Path exhaustion discards state; Exit ends this candidate's walk, not later ones.
    /// Upstream deduplicates instruction addresses globally within each walk, even
    /// when converging branches carry different state.
    ///
    /// Follow can leave the recorded function range. Active search bounds filter
    /// visited instructions, but upstream may read a target before visiting it.
    /// Metadata, visitor, memory and invalid-instruction errors stop later candidates.
    ///
    /// ```
    /// use binary_bloodhound::{BinaryMatcher, Control};
    /// use iced_x86::FlowControl;
    /// let matcher = BinaryMatcher::address(0x1008)
    ///     .walk_disassembly(|address| (address, 0_usize), |(address, count), instruction| {
    ///         Ok(if instruction.flow_control() == FlowControl::Return {
    ///             Control::Return((address, count))
    ///         } else {
    ///             Control::Continue((address, count + 1))
    ///         })
    ///     });
    /// ```
    pub fn walk_disassembly<S, R, Init, F>(self, initial: Init, visitor: F) -> Matcher<'scope, I, R>
    where
        S: Clone + Send + 'scope,
        R: Send + 'scope,
        Init: Fn(T) -> S + Send + Sync + 'scope,
        F: Fn(S, &iced_x86::Instruction) -> Result<Control<S, R>> + Send + Sync + 'scope,
    {
        self.with_context().try_expand(move |(ctx, candidate)| {
            let Some(function) = root_entry(ctx.image(), candidate.address())? else {
                return Ok(Vec::new());
            };
            disassembly::walk(ctx, function, initial(candidate), &visitor)
        })
    }

    /// Extract raw addresses, preserving order and duplicates.
    pub fn addresses(self) -> Matcher<'scope, I, u64, C> {
        self.map(|node| node.address())
    }

    /// Resolve signed little-endian 32-bit displacements at each input address.
    /// The base is address + 4, so inputs must point at the displacement itself.
    /// Preserve order and duplicates; propagate read and address-overflow errors.
    /// Targets need not be mapped in the image.
    ///
    /// ```
    /// use binary_bloodhound::BinaryMatcher;
    /// # fn example() -> patternsleuth::resolvers::Result<()> {
    /// let global_pointer = BinaryMatcher::patterns(["48 8B 05 | ?? ?? ?? ??"])?
    ///     .rip4()
    ///     .deref();
    /// # Ok(())
    /// # }
    /// ```
    pub fn rip4(self) -> Matcher<'scope, I, u64, C> {
        use patternsleuth::MemoryTrait;

        self.with_context().try_map(|(ctx, node)| {
            let address = node.address();
            let base = address.checked_add(4).ok_or_else(|| {
                ResolveError::new_msg(format!("RIP-relative base overflow at {address:#x}"))
            })?;
            let displacement = i64::from(ctx.image().memory.i32_le(address)?);
            base.checked_add_signed(displacement).ok_or_else(|| {
                ResolveError::new_msg(format!(
                    "RIP-relative target overflow at {address:#x}: {displacement}"
                ))
            })
        })
    }

    /// Read little-endian u64 values at each input address, without alignment requirements.
    /// Preserve order and duplicates; propagate read and address-overflow errors.
    pub fn read_u64(self) -> Matcher<'scope, I, u64, C> {
        use patternsleuth::MemoryTrait;

        self.with_context().try_map(|(ctx, node)| {
            let address = node.address();
            address.checked_add(8).ok_or_else(|| {
                ResolveError::new_msg(format!("u64 read address overflow at {address:#x}"))
            })?;
            Ok(ctx.image().memory.u64_le(address)?)
        })
    }

    /// Read absolute 64-bit pointers; equivalent to read_u64 on the supported images.
    /// The returned pointer destinations need not be mapped in the image.
    pub fn deref(self) -> Matcher<'scope, I, u64, C> {
        self.read_u64()
    }

    /// Find typed data-reference instruction sites using the existing scan heuristics.
    pub fn references(self) -> Matcher<'scope, I, InstructionSite> {
        self.into_variable().then(stages::references())
    }

    /// Find incoming direct call/jump instruction addresses, not function entries.
    pub fn callers(self) -> Matcher<'scope, I, InstructionSite> {
        self.into_variable().then(stages::callers())
    }

    /// Map to root-function metadata; skip unknown functions and propagate errors.
    pub fn root_functions(self) -> Matcher<'scope, I, FunctionEntry> {
        self.with_context()
            .filter_modify(|(ctx, node)| root_entry(ctx.image(), node.address()))
    }

    /// Inspect outgoing calls once, retaining both instruction sites and targets.
    /// Interior inputs start at their containing root entry; unknown functions are skipped.
    pub fn calls(self) -> Matcher<'scope, I, Call> {
        self.with_context()
            .try_expand(|(ctx, node)| function_calls(ctx, node.address()))
    }

    /// Return outgoing direct near-call targets; exclude indirect calls and tail jumps.
    pub fn callees(self) -> Matcher<'scope, I, Address> {
        self.calls().map(|call| call.target)
    }

    pub fn call_sites(self) -> Matcher<'scope, I, InstructionSite> {
        self.calls().map(|call| call.site)
    }

    /// Resolve inputs once, concatenate references then callers, and map to root entries.
    pub fn xrefs(self) -> Matcher<'scope, I, FunctionEntry> {
        self.addresses()
            .into_variable()
            .then(stages::references::<u64>().union(stages::callers()))
            .then(stages::root_functions())
    }

    /// Add a signed offset without wrapping, retaining cardinality.
    pub fn offset(self, offset: i64) -> Matcher<'scope, I, u64, C> {
        self.addresses().modify_with(move |address| {
            address.checked_add_signed(offset).ok_or_else(|| {
                ResolveError::new_msg(format!("address offset overflow: {address:#x} + {offset}"))
            })
        })
    }
}

impl<'scope, I: Send + 'scope, C: Cardinality> Matcher<'scope, I, u64, C> {
    /// Transform each result into an absolute address, stopping at the first error.
    pub fn modify_with<F>(self, func: F) -> Self
    where
        F: Fn(u64) -> Result<u64> + Send + Sync + 'scope,
    {
        self.try_map(func)
    }
}

/// Typed stages for composing address, instruction, function, and call results.
pub mod stages {
    use super::*;

    /// Collect one instruction vector per function using the current search bounds.
    pub fn disassemble<'scope>() -> Matcher<'scope, Vec<FunctionEntry>, Vec<iced_x86::Instruction>>
    {
        Matcher::items::<FunctionEntry>().disassemble()
    }

    /// Fold each address-bearing candidate's root, initializing from the original candidate.
    pub fn walk_disassembly<'scope, T, S, R, Init, F>(
        initial: Init,
        visitor: F,
    ) -> Matcher<'scope, Vec<T>, R>
    where
        T: HasAddress + Send + 'scope,
        S: Clone + Send + 'scope,
        R: Send + 'scope,
        Init: Fn(T) -> S + Send + Sync + 'scope,
        F: Fn(S, &iced_x86::Instruction) -> Result<Control<S, R>> + Send + Sync + 'scope,
    {
        Matcher::items::<T>().walk_disassembly(initial, visitor)
    }

    /// Resolve signed 4-byte displacements relative to the end of each displacement.
    pub fn rip4<'scope, T: HasAddress + Send + 'scope>() -> Matcher<'scope, Vec<T>, u64> {
        Matcher::items::<T>().rip4()
    }

    /// Read little-endian u64 values, checking the read range before accessing memory.
    pub fn read_u64<'scope, T: HasAddress + Send + 'scope>() -> Matcher<'scope, Vec<T>, u64> {
        Matcher::items::<T>().read_u64()
    }

    /// Read absolute 64-bit pointers without validating their destinations.
    pub fn deref<'scope, T: HasAddress + Send + 'scope>() -> Matcher<'scope, Vec<T>, u64> {
        read_u64()
    }

    /// Data-reference sites, including references via stored pointers; no metadata required.
    pub fn references<'scope, T: HasAddress + Send + 'scope>()
    -> Matcher<'scope, Vec<T>, InstructionSite> {
        Matcher::items::<T>()
            .map(|address| address.address())
            .then(Matcher::from_async(|addresses: Vec<u64>, ctx| {
                Box::pin(async move {
                    Ok(ctx
                        .references(&addresses, false)
                        .await
                        .into_iter()
                        .map(InstructionSite)
                        .collect())
                })
            }))
    }

    /// Incoming direct call/jump sites, including targets via stored pointers.
    pub fn callers<'scope, T: HasAddress + Send + 'scope>()
    -> Matcher<'scope, Vec<T>, InstructionSite> {
        Matcher::items::<T>()
            .map(|address| address.address())
            .then(Matcher::from_async(|addresses: Vec<u64>, ctx| {
                Box::pin(async move {
                    Ok(ctx
                        .references(&addresses, true)
                        .await
                        .into_iter()
                        .map(InstructionSite)
                        .collect())
                })
            }))
    }

    /// Map addresses to root-function metadata; skip unknown functions, retaining duplicates.
    ///
    /// ```
    /// use binary_bloodhound::BinaryMatcher;
    /// let matcher = BinaryMatcher::address(0x1000)
    ///     .root_functions()
    ///     .filter(|function| function.size() >= 64)
    ///     .map(|function| function.start);
    /// ```
    pub fn root_functions<'scope, T: HasAddress + Send + 'scope>()
    -> Matcher<'scope, Vec<T>, FunctionEntry> {
        Matcher::items::<T>().root_functions()
    }

    /// Reachable direct calls from each containing root, ordered by input then call-site IP.
    /// Excludes indirect calls and tail jumps; memory, metadata, and decode errors propagate.
    pub fn calls<'scope, T: HasAddress + Send + 'scope>() -> Matcher<'scope, Vec<T>, Call> {
        Matcher::items::<T>().calls()
    }
}

fn root_entry(
    image: &patternsleuth::image::Image<'_>,
    address: u64,
) -> Result<Option<FunctionEntry>> {
    let Some(function) = root_function(image, address)? else {
        return Ok(None);
    };
    if function.range.end < function.range.start {
        return Err(ResolveError::new_msg(format!(
            "invalid function range: {:#x}..{:#x}",
            function.range.start, function.range.end
        )));
    }
    Ok(Some(FunctionEntry {
        start: function.range.start,
        end: function.range.end,
        unwind: (function.unwind != 0).then_some(function.unwind),
    }))
}

fn root_function(
    image: &patternsleuth::image::Image<'_>,
    address: u64,
) -> std::result::Result<Option<patternsleuth::RuntimeFunction>, patternsleuth::MemoryAccessError> {
    match &image.image_type {
        #[cfg(feature = "image-pe")]
        patternsleuth::image::ImageType::PEImage(pe) => {
            use patternsleuth::{MemoryAccessError, MemoryTrait};

            let range = &pe.exception_directory_range;
            let length = range
                .end
                .checked_sub(range.start)
                .ok_or(MemoryAccessError::MemoryOutOfBoundsError)?;
            if length == 0 {
                return Ok(None);
            }
            if length < 12 {
                return Err(MemoryAccessError::MemoryOutOfBoundsError);
            }
            let first = image
                .base_address
                .checked_add(u64::from(image.memory.u32_le(range.start)?))
                .ok_or(MemoryAccessError::MemoryOutOfBoundsError)?;
            // Upstream's inclusive binary search underflows for empty tables or
            // addresses below the first entry in the sorted PE function table.
            if address < first {
                return Ok(None);
            }
        }
        #[cfg(feature = "image-elf")]
        patternsleuth::image::ImageType::ElfImage(_) => {}
    }
    image.get_root_function(address)
}

/// Visit reachable blocks without following branches outside the containing root.
fn function_calls(ctx: MatchContext<'_, '_>, address: u64) -> Result<Vec<Call>> {
    use patternsleuth::MemoryTrait;

    let image = ctx.image();
    let Some(root) = root_function(image, address)? else {
        return Ok(Vec::new());
    };
    let entry = root.range.start;
    let bounds = ctx.bounds();
    let start = bounds
        .as_ref()
        .map_or(entry, |range| entry.max(range.start));
    let mut pending = vec![start];
    let mut visited = HashSet::new();
    let mut calls = Vec::new();
    while let Some(block) = pending.pop() {
        if visited.contains(&block)
            || bounds.as_ref().is_some_and(|range| !range.contains(&block))
            || root_function(image, block)?.map(|f| f.range.start) != Some(entry)
        {
            continue;
        }
        let bytes = image.memory.range_from(block..)?;
        let length = bounds.as_ref().map_or(bytes.len(), |range| {
            usize::try_from(range.end - block)
                .unwrap_or(usize::MAX)
                .min(bytes.len())
        });
        let mut decoder = Decoder::with_ip(64, &bytes[..length], block, DecoderOptions::NONE);
        while decoder.can_decode() {
            let ip = decoder.ip();
            if root_function(image, ip)?.map(|f| f.range.start) != Some(entry)
                || !visited.insert(ip)
            {
                break;
            }
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                if bounds.is_some() && decoder.last_error() == iced_x86::DecoderError::NoMoreBytes {
                    break;
                }
                return Err(ResolveError::new_msg(format!(
                    "invalid instruction at {ip:#x}"
                )));
            }
            match instruction.flow_control() {
                FlowControl::Call if instruction.is_call_near() => {
                    calls.push(Call {
                        site: InstructionSite(ip),
                        target: Address(instruction.near_branch_target()),
                    });
                }
                FlowControl::ConditionalBranch => pending.push(instruction.near_branch_target()),
                FlowControl::UnconditionalBranch => {
                    pending.push(instruction.near_branch_target());
                    break;
                }
                FlowControl::Return | FlowControl::IndirectBranch | FlowControl::Exception => break,
                _ => {}
            }
        }
    }
    calls.sort_unstable_by_key(|call| call.site.0);
    Ok(calls)
}
