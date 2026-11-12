//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/static_construct_object.rs>

use std::collections::HashSet;

#[cfg(feature = "image-elf")]
use super::scan::scan;
use binary_bloodhound::BinaryMatcher;
use futures::join;

use super::util;
use patternsleuth::{
    disassemble::{Control, disassemble},
    resolvers::{ensure_one, impl_resolver_singleton},
};

/// class UObject * __cdecl StaticConstructObject_Internal(struct FStaticConstructObjectParameters const &)
pub use super::models::objects::StaticConstructObjectInternal;
impl_resolver_singleton!(all, StaticConstructObjectInternal, |ctx| async {
    let any = join!(
        ctx.resolve(StaticConstructObjectInternalPatterns::resolver()),
        ctx.resolve(StaticConstructObjectInternalString::resolver()),
    );

    Ok(Self(ensure_one(
        [any.0.map(|r| r.0), any.1.map(|r| r.0)]
            .into_iter()
            .filter_map(Result::ok),
    )?))
});

pub use super::models::objects::StaticConstructObjectInternalPatterns;
impl_resolver_singleton!(all, StaticConstructObjectInternalPatterns, |ctx| async {
    let patterns = [
        "48 89 44 24 28 C7 44 24 20 00 00 00 00 E8 | ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B ?? 24",
        "E8 | ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C0 E9 ?? 32 88 ?? ?? ?? ?? 80 E1 01 30 88 ?? ?? ?? ?? 48",
        "E8 | ?? ?? ?? ?? 48 8B D8 48 39 75 30 74 15",
        /*
               03f4df3f c6  44  24       MOV        byte ptr [RSP  + local_88 ],0x0
                        30  00
               03f4df44 0f  57  c0       XORPS      XMM0 ,XMM0
               03f4df47 0f  11  44       MOVUPS     xmmword ptr [RSP  + local_80[0] ],XMM0
                        24  38
               03f4df4c 4c  89  ff       MOV        RDI ,R15
               03f4df4f e8  2c  b6       CALL       StaticConstructObject_Internal                   undefined StaticConstructObject_
                        02  03
               03f4df54 48  89  c3       MOV        RBX ,RAX

        */
        "c6 44 24 30  00 0f 57 c0 0f 11 44 24 38 4c 89 ff e8 | ?? ?? ?? ?? 48 89",
    ];

    BinaryMatcher::patterns(patterns)?
        .rip4()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

pub use super::models::objects::StaticConstructObjectInternalString;
impl_resolver_singleton!(collect, StaticConstructObjectInternalString);
impl_resolver_singleton!(ElfImage, StaticConstructObjectInternalString, |ctx| async {
    let strings = scan(
        ctx,
        util::utf16_pattern("NewObject with empty name can\'t be used to create default"),
    )
    .await;
    let refs = util::scan_xrefs(ctx, &strings).await;
    let target_addr = refs
        .iter()
        .take(6)
        .flat_map(|&addr| -> Option<Vec<(u64, u64)>> {
            // find e8 call
            let mut callsites = Vec::default();
            // ...06f83ff0 is the real one?
            disassemble(ctx.image(), addr, |inst| {
                let cur = inst.ip();
                if !(addr..addr + 130).contains(&cur) {
                    return Ok(Control::Break);
                }
                if !inst.is_call_near_indirect() && inst.is_call_near() {
                    callsites.push(inst.ip_rel_memory_address());
                }
                Ok(Control::Continue)
            })
            .ok()?;
            // the seq is always
            // call FStaticConstructObjectParameters::FStaticConstructObjectParameters .0
            // call StaticConstructObjectInternal .1

            let callsites = callsites
                .iter()
                .zip(callsites.iter().skip(1))
                .map(|(&x, &y)| (x, y))
                .collect::<Vec<_>>();
            Some(callsites)
        })
        .reduce(|x, y| {
            let x: HashSet<(u64, u64)> = HashSet::from_iter(x);
            let y: HashSet<(u64, u64)> = HashSet::from_iter(y);
            let z = x.intersection(&y);
            z.cloned().collect()
        })
        .unwrap_or_default();
    Ok(Self(ensure_one(target_addr)?.1))
});

impl_resolver_singleton!(PEImage, StaticConstructObjectInternalString, |ctx| async {
    use std::collections::HashMap;

    use iced_x86::{Code, FlowControl, OpKind, Register};
    use itertools::Itertools;

    use patternsleuth::{
        MemoryTrait,
        disassemble::disassemble_single,
        image::Image,
        resolvers::{Result, bail_out},
        scanner::Pattern,
    };

    // StaticConstructObject_Internal contains magic RF-flags test
    fn check_is_static_construct(img: &Image<'_>, f: u64) -> Result<bool> {
        let mut is = false;
        disassemble(img, f, |inst| {
            let cur = inst.ip();
            if Some(f) != img.get_root_function(cur)?.map(|f| f.range.start) {
                return Ok(Control::Break);
            }

            if inst.immediate32() == 0x10000080 {
                is = true;
                return Ok(Control::Exit);
            }

            Ok(Control::Continue)
        })?;
        Ok(is)
    }

    fn deref_thunk(img: &Image<'_>, mut callee: u64) -> Result<u64> {
        if let Some(inst) = disassemble_single(img, callee)?
            && inst.flow_control() == FlowControl::UnconditionalBranch
        {
            callee = inst.near_branch_target();
        }
        Ok(callee)
    }

    // phase 1: class-name anchors
    fn check_is_new_object(img: &Image<'_>, f: u64) -> Result<bool> {
        let cmp = "NewObject with empty name can't"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect_vec();

        let check = |f| -> Result<bool> {
            let mut is = false;
            disassemble(img, f, |inst| {
                let cur = inst.ip();
                if Some(f) != img.get_root_function(cur)?.map(|f| f.range.start) {
                    return Ok(Control::Break);
                }

                if inst.code() == Code::Lea_r64_m
                    && inst.memory_base() == Register::RIP
                    && inst.op0_kind() == OpKind::Register
                    && inst.op1_kind() == OpKind::Memory
                {
                    let ptr = inst.ip_rel_memory_address();
                    if img
                        .memory
                        .range(ptr..ptr + cmp.len() as u64)
                        .map(|data| data == cmp)
                        .unwrap_or(false)
                    {
                        is = true;
                        return Ok(Control::Exit);
                    }
                }

                Ok(Control::Continue)
            })?;
            Ok(is)
        };

        if check(f)? {
            return Ok(true);
        }
        // sometimes can be a call deep so check all outgoing calls as well
        for call in util::find_calls(img, f)? {
            let f = deref_thunk(img, call.callee)?;

            if check(f)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    let strings = BinaryMatcher::patterns(
        [
            "UBehaviorTreeManager\0",
            "ULeaderboardFlushCallbackProxy\0",
            "UPlayMontageCallbackProxy\0",
        ]
        .map(util::utf16_pattern),
    )?
    .resolve(ctx)
    .await?;

    let refs_indirect = BinaryMatcher::patterns(
        strings
            .iter()
            .map(|s| Pattern::from_bytes(s.value.to_le_bytes().into()).unwrap()),
    )?
    .resolve(ctx)
    .await?;

    let fns = BinaryMatcher::patterns(strings.iter().chain(&refs_indirect).flat_map(|s| {
        let s = *s.value;
        [
            format!("48 8d ?? X0x{s:X}"),
            format!("4c 8d ?? X0x{s:X}"),
            format!("48 8d ?? X0x{:X}", s + 2),
            format!("4c 8d ?? X0x{:X}", s + 2),
        ]
    }))?
    .with_context()
    .try_map_filter(|(ctx, node)| {
        Ok(ctx
            .image()
            .get_root_function(*node.value)?
            .map(|f| f.range.start))
    })
    .resolve(ctx)
    .await?;

    let new_object = {
        let mut fns = fns.into_iter().map(|node| *node.value).collect_vec();

        let mut new_object = None;
        for f in &fns {
            if check_is_new_object(ctx.image(), *f)? {
                new_object = Some(*f);
                break;
            }
        }

        'root: for _ in 0..2 {
            enum CallType {
                Call,
                Jump,
            }

            if new_object.is_none() {
                fns = BinaryMatcher::tagged_capture_patterns(fns.into_iter().flat_map(|f| {
                    [
                        (CallType::Call, format!("e8 X0x{f:x}")),
                        (CallType::Jump, format!("e9 X0x{f:x}")),
                    ]
                }))?
                .with_context()
                .try_map_filter(|(ctx, node)| {
                    Ok(match node.tag.as_ref() {
                        CallType::Call => ctx
                            .image()
                            .get_root_function(node.address)?
                            .map(|f| f.range.start),
                        CallType::Jump => Some(node.address),
                    })
                })
                .resolve(ctx)
                .await?
                .into_iter()
                .map(|node| *node.value)
                .collect_vec();
            }

            for f in &fns {
                if check_is_new_object(ctx.image(), *f)? {
                    new_object = Some(*f);
                    break 'root;
                }
            }
        }
        new_object
    };

    if let Some(new_object) = new_object {
        let mut checked = HashSet::new();
        for call in util::find_calls(ctx.image(), new_object)? {
            if checked.insert(call.callee) {
                let f = deref_thunk(ctx.image(), call.callee)?;

                if check_is_static_construct(ctx.image(), f)? {
                    return Ok(Self(call.callee));
                }
            }
        }
        // try one call deeper
        for f in checked.clone().into_iter() {
            for call in util::find_calls(ctx.image(), f)? {
                if checked.insert(call.callee)
                    && check_is_static_construct(ctx.image(), call.callee)?
                {
                    return Ok(Self(call.callee));
                }
            }
        }
    }

    // phase 2: empty-name consensus
    let new_object_fns = BinaryMatcher::pattern(util::utf16_pattern(
        "NewObject with empty name can't be used to create default",
    ))
    .references()
    .with_context()
    .map_filter(|(ctx, r)| {
        ctx.image()
            .get_root_function(r.value.0)
            .ok()
            .flatten()
            .map(|f| f.range.start)
    })
    .resolve(ctx)
    .await?
    .into_iter()
    .map(|node| *node.value)
    .collect::<HashSet<_>>()
    .into_iter()
    .collect::<Vec<_>>();

    let mut counts: HashMap<u64, usize> = HashMap::new();
    for depth in 0..2 {
        for &f in &new_object_fns {
            for call in util::find_calls(ctx.image(), f)? {
                let callee = deref_thunk(ctx.image(), call.callee)?;
                if depth == 0 {
                    if check_is_static_construct(ctx.image(), callee)? {
                        *counts.entry(callee).or_default() += 1;
                    }
                } else {
                    for inner in util::find_calls(ctx.image(), callee)? {
                        let inner = deref_thunk(ctx.image(), inner.callee)?;
                        if check_is_static_construct(ctx.image(), inner)? {
                            *counts.entry(inner).or_default() += 1;
                        }
                    }
                }
            }
        }
        if !counts.is_empty() {
            break;
        }
    }

    let Some((addr, _)) = counts.into_iter().max_by_key(|(_, n)| *n) else {
        bail_out!("could not find StaticConstructObject_Internal call");
    };
    Ok(Self(addr))
});

#[cfg(all(test, feature = "image-pe"))]
mod cleanup_tests {
    use super::*;
    use object::SectionKind;
    use patternsleuth::{
        NamedMemorySection,
        image::{Image, ImageType},
    };

    fn image(bytes: Vec<u8>) -> Image<'static> {
        let image = super::super::tests::image(bytes);
        Image::from_memory(
            0x1000,
            image.memory,
            ImageType::PEImage(patternsleuth::image::pe::PEImage {
                exception_directory_range: 0x3000..0x3030,
                exception_children_cache: Default::default(),
            }),
        )
        .with_section(NamedMemorySection::new(
            ".pdata".into(),
            0x3000,
            SectionKind::ReadOnlyData,
            (0..4_u32)
                .flat_map(|index| [index * 0x100, index * 0x100 + 0x80, 0x2100])
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>(),
        ))
        .with_section(NamedMemorySection::new(
            ".xdata".into(),
            0x3100,
            SectionKind::ReadOnlyData,
            vec![1, 0, 0, 0],
        ))
    }

    fn relative(bytes: &mut [u8], offset: usize, prefix: &[u8], target: u64) {
        bytes[offset..offset + prefix.len()].copy_from_slice(prefix);
        let at = offset + prefix.len();
        let displacement = i32::try_from(target as i64 - (0x1000 + at + 4) as i64).unwrap();
        bytes[at..at + 4].copy_from_slice(&displacement.to_le_bytes());
    }

    #[test]
    fn anchor_pipelines_match_native_direct_indirect_ancestors_and_consensus_fallback() {
        for (anchor, indirect, thunk) in [
            (true, false, false),
            (true, true, false),
            (false, false, false),
            (true, false, true),
            (false, false, true),
        ] {
            for depth in 0..3 {
                let mut bytes = vec![0x90; 0x1000];
                for start in [0, 0x100, 0x200, 0x300] {
                    bytes[start + 0x40] = 0xc3;
                }
                for (offset, text) in [
                    (0x800, "UBehaviorTreeManager\0"),
                    (
                        0x900,
                        "NewObject with empty name can't be used to create default",
                    ),
                ] {
                    if offset == 0x800 && !anchor {
                        continue;
                    }
                    let text = util::utf16(text);
                    bytes[offset..offset + text.len()].copy_from_slice(&text);
                }
                bytes[0x700..0x708].copy_from_slice(&0x1800_u64.to_le_bytes());
                relative(
                    &mut bytes,
                    0,
                    &[0x48, 0x8d, 0x0d],
                    if indirect { 0x1700 } else { 0x1800 },
                );
                // A second matching LEA retains duplicate candidate roots.
                relative(
                    &mut bytes,
                    0x10,
                    &[0x4c, 0x8d, 0x05],
                    if indirect { 0x1702 } else { 0x1802 },
                );
                let new_object = if depth == 0 { 0 } else { 0x100 };
                relative(&mut bytes, new_object + 0x20, &[0x48, 0x8d, 0x15], 0x1900);
                relative(
                    &mut bytes,
                    new_object + 0x30,
                    &[0xe8],
                    if thunk { 0x1250 } else { 0x1200 },
                );
                relative(&mut bytes, 0x250, &[0xe9], 0x1200);
                if depth == 1 {
                    relative(&mut bytes, 0x100, &[0xe8], 0x1000);
                } else if depth == 2 {
                    relative(&mut bytes, 0x300, &[0xe9], 0x1000);
                    relative(&mut bytes, 0x100, &[0xe8], 0x1300);
                }
                bytes[0x200..0x206].copy_from_slice(&[0xb8, 0x80, 0, 0, 0x10, 0xc3]);
                let image = image(bytes);
                let result = image
                    .resolve(StaticConstructObjectInternalString::resolver())
                    .unwrap();
                let upstream = image.resolve(patternsleuth::resolvers::unreal::static_construct_object::StaticConstructObjectInternalString::resolver()).unwrap();
                let expected = if anchor && thunk { 0x1250 } else { 0x1200 };

                assert_eq!(
                    result.0, expected,
                    "anchor={anchor}, indirect={indirect}, depth={depth}, thunk={thunk}"
                );
                assert_eq!(result.0, upstream.0);
            }
        }
    }
}
