use std::sync::Arc;

use futures::future::BoxFuture;
use patternsleuth::{
    MemoryTrait,
    resolvers::{ResolveError, Result},
};

use crate::{
    Address, Call, Cardinality, Composition, Control, FunctionEntry, HasAddress, InstructionSite,
    MatchContext, Matcher, Trace, Variable, disassembly,
    functions::{function_calls, root_entry},
    pipeline::Run,
};

impl<
    'scope,
    I: Send + 'scope,
    T: HasAddress + Send + Sync + 'scope,
    P: Send + Sync + 'scope,
    C: Cardinality,
> Matcher<'scope, I, T, C, P>
{
    pub fn addresses(self) -> Matcher<'scope, I, u64, C, Trace<T, P>> {
        self.map(HasAddress::address)
    }
    pub fn offset(self, offset: i64) -> Matcher<'scope, I, u64, C, Trace<T, P>> {
        self.try_map(move |node| {
            let address = node.address();
            address.checked_add_signed(offset).ok_or_else(|| {
                ResolveError::new_msg(format!("address offset overflow: {address:#x} + {offset}"))
            })
        })
    }
    /// Checked address + 4 + signed i32 displacement. Preserve duplicates and
    /// cardinality; returned destinations need not be mapped.
    pub fn rip4(self) -> Matcher<'scope, I, u64, C, Trace<T, P>> {
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
    pub fn read_u64(self) -> Matcher<'scope, I, u64, C, Trace<T, P>> {
        self.with_context().try_map(|(ctx, node)| {
            let address = node.address();
            address.checked_add(8).ok_or_else(|| {
                ResolveError::new_msg(format!("u64 read address overflow at {address:#x}"))
            })?;
            Ok(ctx.image().memory.u64_le(address)?)
        })
    }
    pub fn deref(self) -> Matcher<'scope, I, u64, C, Trace<T, P>> {
        self.read_u64()
    }
    pub fn root_functions(self) -> Matcher<'scope, I, FunctionEntry, Variable, Trace<T, P>> {
        self.with_context()
            .try_map_filter(|(ctx, node)| root_entry(ctx.image(), node.address()))
    }
    /// Find data-reference sites per candidate, sequentially in input order.
    /// Retain native indirect-pointer heuristics and active search bounds.
    pub fn references(self) -> Matcher<'scope, I, InstructionSite, Variable, Trace<T, P>> {
        self.reference_sites(ReferenceKind::Data)
    }
    pub fn callers(self) -> Matcher<'scope, I, InstructionSite, Variable, Trace<T, P>> {
        self.reference_sites(ReferenceKind::Calls)
    }
    fn reference_sites(
        self,
        kind: ReferenceKind,
    ) -> Matcher<'scope, I, InstructionSite, Variable, Trace<T, P>> {
        Matcher::from_run(References {
            matcher: self,
            kind,
        })
    }
    pub fn xrefs(
        self,
    ) -> Matcher<'scope, I, FunctionEntry, Variable, Trace<InstructionSite, Trace<T, P>>> {
        self.reference_sites(ReferenceKind::Both).root_functions()
    }
    pub fn calls(self) -> Matcher<'scope, I, Call, Variable, Trace<T, P>> {
        self.with_context()
            .try_expand(|(ctx, node)| function_calls(ctx, node.address()))
    }
    pub fn callees(self) -> Matcher<'scope, I, Address, Variable, Trace<Call, Trace<T, P>>> {
        self.calls().map(|node| node.value.target)
    }
    pub fn call_sites(
        self,
    ) -> Matcher<'scope, I, InstructionSite, Variable, Trace<Call, Trace<T, P>>> {
        self.calls().map(|node| node.value.site)
    }
    /// Initialize from the original node; emitted results retain that node as parent.
    /// Resolve its root internally; unknown roots skip initialization. Clone state
    /// for queued paths. Return emits; Break ends a path; Exit ends one candidate.
    /// Native visited-IP deduplication remains global within each candidate's walk.
    /// Follow may leave the root's range; native decoding can read targets before
    /// search-bound filtering. Visitor and native errors stop later candidates.
    pub fn walk_disassembly<S, R, Init, F>(
        self,
        initial: Init,
        visitor: F,
    ) -> Matcher<'scope, I, R, Variable, Trace<T, P>>
    where
        S: Clone + Send + 'scope,
        R: Send + Sync + 'scope,
        Init: Fn(&Trace<T, P>) -> S + Send + Sync + 'scope,
        F: Fn(S, &iced_x86::Instruction) -> Result<Control<S, R>> + Send + Sync + 'scope,
    {
        self.with_context().try_expand(move |(ctx, candidate)| {
            let Some(function) = root_entry(ctx.image(), candidate.address())? else {
                return Ok(Vec::new());
            };
            disassembly::walk(ctx, function, initial(candidate), &visitor)
        })
    }
}

#[derive(Clone, Copy)]
enum ReferenceKind {
    Data,
    Calls,
    Both,
}

struct References<'scope, I, T, P, C: Cardinality> {
    matcher: Matcher<'scope, I, T, C, P>,
    kind: ReferenceKind,
}
impl<
    'scope,
    I: Send + 'scope,
    T: HasAddress + Send + Sync + 'scope,
    P: Send + Sync + 'scope,
    C: Cardinality,
> Run<I, Trace<InstructionSite, Trace<T, P>>> for References<'scope, I, T, P, C>
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<Trace<InstructionSite, Trace<T, P>>>>>
    where
        I: 'ctx,
        Trace<InstructionSite, Trace<T, P>>: 'ctx,
    {
        Box::pin(async move {
            let mut result = Vec::new();
            for node in self.matcher.run_in(input, ctx).await? {
                let address = node.address();
                let calls_only = matches!(self.kind, ReferenceKind::Calls);
                let mut addresses = ctx.references(&[address], calls_only).await;
                if matches!(self.kind, ReferenceKind::Both) {
                    addresses.extend(ctx.references(&[address], true).await);
                    let mut seen = std::collections::HashSet::new();
                    addresses.retain(|address| seen.insert(*address));
                }
                result.extend(Trace::children(
                    addresses.into_iter().map(InstructionSite),
                    node,
                ));
            }
            Ok(result)
        })
    }
}

struct Sub<'scope, I, P, T, Q, C: Cardinality, D: Cardinality> {
    functions: Matcher<'scope, I, FunctionEntry, C, P>,
    inner: Matcher<'scope, (), T, D, Q>,
}
impl<
    'scope,
    I: Send + 'scope,
    P: Send + Sync + 'scope,
    T: Send + Sync + 'scope,
    Q: Send + Sync + 'scope,
    C: Cardinality,
    D: Cardinality,
> Run<I, Trace<T, Composition<Trace<FunctionEntry, P>, Q>>> for Sub<'scope, I, P, T, Q, C, D>
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<Trace<T, Composition<Trace<FunctionEntry, P>, Q>>>>>
    where
        I: 'ctx,
        Trace<T, Composition<Trace<FunctionEntry, P>, Q>>: 'ctx,
    {
        Box::pin(async move {
            let mut result = Vec::new();
            for function in self.functions.run_in(input, ctx).await? {
                let inner = ctx.within(function.checked_range()?);
                if inner.bounds().is_some_and(|range| range.start < range.end) {
                    let parent = Arc::new(function);
                    let nodes = D::into_items(self.inner.run_resolved_in((), inner).await?);
                    result.extend(
                        nodes
                            .into_iter()
                            .map(|node| node.compose(Arc::clone(&parent))),
                    );
                }
            }
            Ok(result)
        })
    }
}

impl<'scope, I: Send + 'scope, P: Send + Sync + 'scope, C: Cardinality>
    Matcher<'scope, I, FunctionEntry, C, P>
{
    #[allow(clippy::should_implement_trait)] // Function-scoped search, not subtraction.
    /// Search inside each function, intersecting nested bounds. Preserve order
    /// and duplicates. Reads and returned targets may leave search bounds.
    ///
    /// ```compile_fail
    /// use binary_bloodhound::BinaryMatcher;
    /// let invalid = BinaryMatcher::address(0x1000).sub(BinaryMatcher::address(0x2000));
    /// ```
    pub fn sub<T: Send + Sync + 'scope, Q: Send + Sync + 'scope, D: Cardinality>(
        self,
        inner: Matcher<'scope, (), T, D, Q>,
    ) -> Matcher<'scope, I, T, Variable, Composition<Trace<FunctionEntry, P>, Q>> {
        Matcher::from_run(Sub {
            functions: self,
            inner,
        })
    }
    /// Collect reachable instructions per function, retaining cardinality. Calls
    /// are not followed; function ranges intersect the current search bounds.
    ///
    /// ```compile_fail
    /// use binary_bloodhound::BinaryMatcher;
    /// let invalid = BinaryMatcher::address(0x1000).disassemble();
    /// ```
    pub fn disassemble(
        self,
    ) -> Matcher<'scope, I, Vec<iced_x86::Instruction>, C, Trace<FunctionEntry, P>> {
        self.disassemble_until(|_| false)
    }
    /// Include the stopping instruction, then terminate only that path. Previously
    /// queued paths still run; the stopped instruction's branch is not followed.
    pub fn disassemble_until<F>(
        self,
        stop: F,
    ) -> Matcher<'scope, I, Vec<iced_x86::Instruction>, C, Trace<FunctionEntry, P>>
    where
        F: Fn(&iced_x86::Instruction) -> bool + Send + Sync + 'scope,
    {
        self.with_context()
            .try_map(move |(ctx, node)| disassembly::collect(ctx, *node.value, &stop))
    }
}

impl<'scope, I: Send + 'scope, P: Send + Sync + 'scope, C: Cardinality>
    Matcher<'scope, I, u64, C, P>
{
    pub fn modify_with<F>(self, func: F) -> Matcher<'scope, I, u64, C, Trace<u64, P>>
    where
        F: Fn(&Trace<u64, P>) -> Result<u64> + Send + Sync + 'scope,
    {
        self.try_map(func)
    }
}

pub mod stages {
    use super::*;

    /// A reusable navigation stage accepting existing immutable nodes.
    pub type Stage<'scope, T, U, P = ()> =
        Matcher<'scope, Vec<Trace<T, P>>, U, Variable, Trace<T, P>>;

    pub fn references<'scope, T: HasAddress + Send + Sync + 'scope, P: Send + Sync + 'scope>()
    -> Stage<'scope, T, InstructionSite, P> {
        Matcher::nodes::<T, P>().references()
    }
    pub fn callers<'scope, T: HasAddress + Send + Sync + 'scope, P: Send + Sync + 'scope>()
    -> Stage<'scope, T, InstructionSite, P> {
        Matcher::nodes::<T, P>().callers()
    }
    pub fn root_functions<'scope, T: HasAddress + Send + Sync + 'scope, P: Send + Sync + 'scope>()
    -> Stage<'scope, T, FunctionEntry, P> {
        Matcher::nodes::<T, P>().root_functions()
    }
    pub fn calls<'scope, T: HasAddress + Send + Sync + 'scope, P: Send + Sync + 'scope>()
    -> Stage<'scope, T, Call, P> {
        Matcher::nodes::<T, P>().calls()
    }
    pub fn rip4<'scope, T: HasAddress + Send + Sync + 'scope, P: Send + Sync + 'scope>()
    -> Stage<'scope, T, u64, P> {
        Matcher::nodes::<T, P>().rip4()
    }
    pub fn read_u64<'scope, T: HasAddress + Send + Sync + 'scope, P: Send + Sync + 'scope>()
    -> Stage<'scope, T, u64, P> {
        Matcher::nodes::<T, P>().read_u64()
    }
    pub fn deref<'scope, T: HasAddress + Send + Sync + 'scope, P: Send + Sync + 'scope>()
    -> Stage<'scope, T, u64, P> {
        read_u64()
    }
    pub fn disassemble<'scope, P: Send + Sync + 'scope>()
    -> Stage<'scope, FunctionEntry, Vec<iced_x86::Instruction>, P> {
        Matcher::nodes::<FunctionEntry, P>().disassemble()
    }
    pub fn walk_disassembly<'scope, T, P, S, R, Init, F>(
        initial: Init,
        visitor: F,
    ) -> Stage<'scope, T, R, P>
    where
        T: HasAddress + Send + Sync + 'scope,
        P: Send + Sync + 'scope,
        S: Clone + Send + 'scope,
        R: Send + Sync + 'scope,
        Init: Fn(&Trace<T, P>) -> S + Send + Sync + 'scope,
        F: Fn(S, &iced_x86::Instruction) -> Result<Control<S, R>> + Send + Sync + 'scope,
    {
        Matcher::nodes::<T, P>().walk_disassembly(initial, visitor)
    }
}
