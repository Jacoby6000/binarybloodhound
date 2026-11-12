//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/guobject_array.rs>

use binary_bloodhound::{BinaryMatcher, Matcher};
use futures::{join, try_join};

use super::scan::scan_patterns;

use super::util;
use patternsleuth::{
    MemoryTrait,
    resolvers::{Result, impl_resolver_singleton, try_ensure_one},
};

pub use super::models::objects::GUObjectArray;
impl_resolver_singleton!(all, GUObjectArray, |ctx| async {
    let relative_patterns = [
        "8B 05 ?? ?? ?? ?? 3B 05 ?? ?? ?? ?? 75 ?? 48 8D 15 ?? ?? ?? ?? 48 8D 0D | ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 05",
        "74 ?? 48 8D 0D | ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01",
        "75 ?? 48 ?? ?? 48 8D 0D | ?? ?? ?? ?? E8 ?? ?? ?? ?? 45 33 C9 4C 89 74 24",
        "45 84 c0 48 c7 41 10 00 00 00 00 b8 ff ff ff ff 4c 8d 1d | ?? ?? ?? ?? 89 41 08 4c 8b d1 4c 89 19 0f 45 05 ?? ?? ?? ?? ff c0 89 41 08 3b 05",
        "81 ce 00 00 00 02 83 e0 fb 89 47 08 48 8d 0d | ?? ?? ?? ?? 48 89 fa 45 31 c0 e8 ?? ?? ?? ??",
        "E8 ?? ?? ?? ?? 8B 05 ?? ?? ?? ?? 8B 0D ?? ?? ?? ?? 03 0D | ?? ?? ?? ?? 29 C8 87 05",
    ];
    // mov imm32 pattern for linux
    let immediate_patterns = [
        /*
        06f97b32 41  39  ee       CMP        R14D ,EBP
        06f97b35 0f  8e  7e       JLE        LAB_06f97cb9
                 01  00  00
        06f97b3b bf  d8  c5       MOV        param_1 ,GUObjectArray
                 ac  0b
        06f97b40 48  8b  74       MOV        param_2 ,qword ptr [RSP  + local_68 ]
                 24  10
        06f97b45 e8  16  d2       CALL       FUN_06f64d60                                     undefined FUN_06f64d60()
                 fc  ff
        06f97b4a e9  6a  01       JMP        LAB_06f97cb9
                 00  00
         */
        "41 39 ee 0f 8e ?? ?? ?? ?? bf | ?? ?? ?? ?? 48 8b 74 24 10 e8 ?? ?? ?? ?? e9",
        /*
        06fa15c8 8b  6f  3c       MOV        EBP ,dword ptr [RDI  + 0x3c ]
        06fa15cb 4c  89  f7       MOV        RDI ,R14
        06fa15ce 31  f6           XOR        ESI ,ESI
        06fa15d0 e8  1b  09       CALL       FUN_06fa1ef0                                     undefined FUN_06fa1ef0()
                 00  00
        06fa15d5 41  39  ef       CMP        R15D ,EBP
        06fa15d8 7e  0d           JLE        LAB_06fa15e7
        06fa15da bf  d8  c5       MOV        EDI ,GUObjectArray
                 ac  0b
        06fa15df 48  89  de       MOV        RSI ,RBX
        06fa15e2 e8  79  37       CALL       FUN_06f64d60                                     undefined FUN_06f64d60()
                 fc  ff
         */
        "8b 6f ?? 4c 89 f7 31 f6 e8 ?? ?? ?? ?? 41 39 ef 7e 0d bf | ?? ?? ?? ?? 48 89 de e8",
    ];
    // `ObjObjects.Num() - ObjFirstGCIndex - <available count>` inlined into a stat update.
    // order and spacing depends on version so capture all three and match against known spacings
    let num_minus_available = BinaryMatcher::capture_patterns([
        "8B 05 [ ?? ?? ?? ?? ] 2B 05 [ ?? ?? ?? ?? ] 2B 05 [ ?? ?? ?? ?? ]",
    ])?
    .try_map_filter(|node| {
        let caps = &node.captures;
        let mut operands = [caps[0].rip4()?, caps[1].rip4()?, caps[2].rip4()?];
        operands.sort_unstable();
        Ok(base_from_operands(operands))
    });

    let (relative_addresses, immediate_addresses, layout_bases) = join!(
        scan_patterns(ctx, relative_patterns),
        scan_patterns(ctx, immediate_patterns),
        num_minus_available.resolve(ctx),
    );

    // Preserve upstream's eager layout validation before lazy address decoding.
    let layout_bases = layout_bases?;
    let immediate_bases = immediate_addresses
        .iter()
        .map(|a| -> Result<_> { Ok(ctx.image().memory.u32_le(*a)? as u64) });

    /// Given the three ascending operand addresses, return the `FUObjectArray` base they belong to
    fn base_from_operands(operands: [u64; 3]) -> Option<u64> {
        [[0x00, 0x24, 0x60], [0x00, 0x24, 0x68], [0x08, 0x20, 0x68]]
            .iter()
            .find_map(|layout| {
                let base = operands[0].checked_sub(layout[0])?;
                layout
                    .iter()
                    .zip(operands)
                    .all(|(offset, operand)| base + offset == operand)
                    .then_some(base)
            })
    }

    Ok(Self(try_ensure_one(
        relative_addresses
            .iter()
            .map(|a| -> Result<_> { Ok(ctx.image().memory.rip4(*a)?) })
            .chain(immediate_bases)
            .chain(layout_bases.iter().map(|node| Ok(*node.value))),
    )?))
});

/// public: void __cdecl FUObjectArray::AllocateUObjectIndex(class UObjectBase *, bool)
pub use super::models::objects::FUObjectArrayAllocateUObjectIndex;
impl_resolver_singleton!(all, FUObjectArrayAllocateUObjectIndex, |ctx| async {
    let message = "Unable to add more objects to disregard for GC pool (Max: %d)\0";
    BinaryMatcher::patterns([util::utf16_pattern(message), util::utf8_pattern(message)])?
        .references()
        .root_functions()
        .addresses()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

/// public: void __cdecl FUObjectArray::FreeUObjectIndex(class UObjectBase *)
pub use super::models::objects::FUObjectArrayFreeUObjectIndex;
impl_resolver_singleton!(all, FUObjectArrayFreeUObjectIndex, |ctx| async {
    let refs = BinaryMatcher::patterns(
        [
            "Removing object (0x%016llx) at index %d but the index points to a different object (0x%016llx)!",
            "Unexpected concurency while adding new object",
        ]
        .into_iter()
        .flat_map(|s| [util::utf16_pattern(s), util::utf8_pattern(s)]),
    )?
    .references();

    // same string is present in both functions so resolve the other so we can filter it out
    let (allocate_uobject, refs) = try_join!(
        ctx.resolve(FUObjectArrayAllocateUObjectIndex::resolver()),
        refs.resolve(ctx),
    )?;

    Matcher::from_nodes(refs)
        .root_functions()
        .addresses()
        .filter(|address| *address.value != allocate_uobject.0)
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

/// void __cdecl UObjectBaseShutdown(void)
/// could be used to determine object listener offsets, but only for recent UE versions
pub use super::models::objects::UObjectBaseShutdown;
impl_resolver_singleton!(collect, UObjectBaseShutdown);

impl_resolver_singleton!(PEImage, UObjectBaseShutdown, |ctx| async {
    let message = "All UObject delete listeners should be unregistered when shutting down the UObject array\0";
    BinaryMatcher::patterns([util::utf16_pattern(message), util::utf8_pattern(message)])?
        .references()
        .root_functions()
        .addresses()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

impl_resolver_singleton!(ElfImage, UObjectBaseShutdown, |ctx| async {
    let message = "All UObject delete listeners should be unregistered when shutting down the UObject array\0";
    BinaryMatcher::patterns([util::utf16_pattern(message), util::utf8_pattern(message)])?
        .references()
        .root_functions()
        // On Linux both functions are not inlined; find the caller.
        .callers()
        .root_functions()
        .addresses()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

#[cfg(test)]
mod tests {
    use super::{BinaryMatcher, util};
    use patternsleuth::resolvers::eval;

    #[test]
    fn mixed_encoding_reference_pipeline_preserves_source_order_and_duplicates() {
        let mut bytes = vec![0x90; 512];
        bytes[0x80..0x84].copy_from_slice(b"one\0");
        bytes[0x90..0x98].copy_from_slice(&util::utf16("one\0"));
        bytes[0xa0..0xa4].copy_from_slice(b"two\0");
        for (offset, target) in [(0x10, 0x1080), (0x20, 0x1090), (0x30, 0x10a0)] {
            bytes[offset..offset + 3].copy_from_slice(&[0x48, 0x8d, 0x05]);
            let displacement = (target as i32 - (0x1000 + offset as i32 + 7)).to_le_bytes();
            bytes[offset + 3..offset + 7].copy_from_slice(&displacement);
        }
        let image = super::super::tests::image(bytes);
        let (old, new) = eval(&image, |ctx| {
            Box::pin(async move {
                let mut strings = Vec::new();
                for text in ["two\0", "one\0", "one\0"] {
                    strings.extend(util::string_pattern(ctx, text).await);
                }
                let old = util::scan_xrefs(ctx, &strings).await;
                let new = BinaryMatcher::patterns(
                    ["two\0", "one\0", "one\0"]
                        .into_iter()
                        .flat_map(|s| [util::utf16_pattern(s), util::utf8_pattern(s)]),
                )?
                .references()
                .resolve(ctx)
                .await?;
                patternsleuth::resolvers::Result::Ok((old, new))
            })
        })
        .unwrap();

        let addresses: Vec<_> = new.iter().map(|node| node.value.0).collect();

        assert_eq!(addresses, old);
        assert_eq!(addresses, [0x1030, 0x1020, 0x1010, 0x1020, 0x1010]);
        assert_eq!(
            new.iter()
                .map(|node| *node.parent().value)
                .collect::<Vec<_>>(),
            [0x10a0, 0x1090, 0x1080, 0x1090, 0x1080]
        );
    }
}
