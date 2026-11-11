//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/fname.rs>

use futures::future::join_all;

#[cfg(feature = "image-pe")]
use super::scan::scan_tagged2;
use super::scan::{scan, scan_tagged};
use binary_bloodhound::BinaryMatcher;
use patternsleuth::scanner::Pattern;

use super::util;
#[cfg(feature = "image-elf")]
use patternsleuth::MemoryTrait;
use patternsleuth::resolvers::ResolveError;
#[cfg(feature = "image-pe")]
use patternsleuth::resolvers::try_ensure_one;
use patternsleuth::{
    Addressable,
    resolvers::{Result, ensure_one, impl_resolver_singleton},
};

/// public: __cdecl FName::FName(wchar_t const *, enum EFindName)
pub use super::models::fname::FNameCtorWchar;
impl_resolver_singleton!(collect, FNameCtorWchar);

// FEngineLoop::LoadPreInitModules constructs each module's FName before loading it.
impl_resolver_singleton!(ElfImage, FNameCtorWchar, |ctx| async {
    use patternsleuth::resolvers::ResolveError;
    use std::collections::HashSet;

    let strings = [
        "\0Engine\0",
        "\0Renderer\0",
        "\0AnimGraphRuntime\0",
        "\0Landscape\0",
        "\0RenderCore\0",
    ];

    // find the strings
    let strings = join_all(strings.iter().map(|s| scan(ctx, util::utf16_pattern(s)))).await;
    let strings: Vec<Vec<_>> = strings
        .into_iter()
        .map(|pats| pats.into_iter().map(|addr| addr + 2).collect())
        .collect();
    // find refs to them
    let refs: Vec<_> = join_all(strings.iter().map(|addr| util::scan_xrefs(ctx, addr))).await;
    let fns: Vec<_> = refs
        .into_iter()
        .flat_map(|addr| util::root_functions(ctx, &addr).ok())
        .collect();

    // find fns of these refs
    let fns = fns
        .into_iter()
        .reduce(|x, y| {
            let x: HashSet<u64> = HashSet::from_iter(x);
            let y: HashSet<u64> = HashSet::from_iter(y);
            x.intersection(&y).cloned().collect::<Vec<_>>()
        })
        .unwrap();

    let load_pre_init_modules = ensure_one(fns)?;
    let pattern = Pattern::new("ba 01 00 00 00 e8 | ?? ?? ?? ??").unwrap();
    // Find the FName constructor call after loading the module name and EFindName.
    let mem = ctx
        .image()
        .memory
        .get_section_containing(load_pre_init_modules)
        .unwrap();
    let index = load_pre_init_modules - mem.address();
    let mut result = None;
    for i in 0..48 {
        if pattern.is_match(mem.data(), mem.address() as usize, (index + i) as usize) {
            result = ctx
                .image()
                .memory
                .rip4(load_pre_init_modules + i + pattern.custom_offset as u64)
                .ok();
        }
    }
    let result = result.ok_or(ResolveError::new_msg("cannot find address"))?;
    Ok(Self(result))
});

impl_resolver_singleton!(PEImage, FNameCtorWchar, |ctx| async {
    use futures::join;
    use iced_x86::{Code, Decoder, DecoderOptions};
    use patternsleuth::{MemoryTrait, resolvers::Context};

    // FName(wchar_t const*, EFindName) prologue
    let ctor = async {
        join_all([
            "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 41 8B F8 33 C9 4C 8B DA 44 8B D1 4C 8B CA 48 85 D2 74 ?? 0F B7 02 66 85 C0",
            "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 48 89 54 24 20 33 C9 41 8B F8 4C 8B D2 44 8B C9 48 85 D2 74 ?? 0F B7 02 66 85 C0",
        ].map(|p| scan(ctx, Pattern::new(p).unwrap())))
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
    };
    let strings = async {
        let strings = ["TGPUSkinVertexFactoryUnlimited\0", "MovementComponent0\0"];
        join_all(strings.iter().map(|s| scan(ctx, util::utf16_pattern(s)))).await
    };
    let patterns = async {
        scan(ctx, Pattern::new("EB 07 48 8D 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 B8 01 00 00 00 E8 | ?? ?? ?? ??").unwrap()).await
    };
    let (ctor, patterns, strings) = join!(ctor, patterns, strings);

    // prefer the direct prologue match when present
    if !ctor.is_empty() {
        return BinaryMatcher::candidates(ctor)
            .ensure_one()
            .map(Self)
            .resolve(ctx)
            .await;
    }

    // sometimes the call gets inlined so use patterns if any match
    if !patterns.is_empty() {
        return BinaryMatcher::candidates(patterns)
            .rip4()
            .ensure_one()
            .map(Self)
            .resolve(ctx)
            .await;
    }

    #[derive(Clone, Copy)]
    enum Tag {
        Direct,
        FirstCall,
    }

    let refs = join_all(strings.iter().flatten().flat_map(|s| {
        [
            (
                Tag::FirstCall,
                format!("48 8d 15 X0x{s:x} 4c 8d 05 ?? ?? ?? ?? 41 b1 01 e8 | ?? ?? ?? ??"),
            ),
            (
                Tag::Direct,
                format!("48 8d 15 X0x{s:x} 48 8d 0d ?? ?? ?? ?? e8 | ?? ?? ?? ??"),
            ),
            (
                Tag::Direct,
                format!(
                    "41 b8 01 00 00 00 48 8d 15 X0x{s:x} 48 8d 0d ?? ?? ?? ?? e9 | ?? ?? ?? ??"
                ),
            ),
        ]
        .into_iter()
        .map(|(t, p)| scan_tagged2(ctx, t, Pattern::new(p).unwrap()))
    }))
    .await;

    Ok(Self(try_ensure_one(refs.iter().flatten().map(
        |(tag, address)| {
            let f = ctx.image().memory.rip4(*address)?;
            match tag {
                Tag::Direct => Ok(f),
                Tag::FirstCall => {
                    let bytes = ctx.image().memory.range(f..f + 0x200)?;
                    let mut decoder = Decoder::with_ip(64, bytes, f, DecoderOptions::NONE);

                    decoder
                        .iter()
                        .find_map(|i| {
                            (i.code() == Code::Call_rel32_64).then_some(i.memory_displacement64())
                        })
                        .context("did not find CALL instruction")
                }
            }
        },
    ))?))
});

/// Can be either of the following:
/// `public: class FString __cdecl FName::ToString(void) const`
/// `public: void __cdecl FName::ToString(class FString &) const`
///
/// They take the same arguments and either can be used as long as the return value isn't used.
///
/// !! Be aware anyone try play with this code in Linux, they're different and you should stick with the
/// second one.
///
pub use super::models::fname::FNameToString;
impl_resolver_singleton!(collect, FNameToString);

impl_resolver_singleton!(ElfImage, FNameToString, |ctx| async {
    BinaryMatcher::patterns([util::utf16_pattern("SkySphereMesh\0")])?
        .ensure_one()
        .try_flat_map(|str_addr| {
            BinaryMatcher::patterns([format!(
                "e8 | ?? ?? ?? ?? 49 8b 5f 10 48 8d 7c 24 30 be 0x{str_addr:08x}"
            )])
        })
        .rip4()
        .ensure_one()
        .map(Self)
        .resolve(ctx)
        .await
});

impl_resolver_singleton!(PEImage, FNameToString, |ctx| async {
    use futures::join;
    use iced_x86::{Code, Decoder, DecoderOptions};
    use patternsleuth::{MemoryTrait, resolvers::Context};

    let patterns = async {
        let patterns = ["56 57 48 83 EC 28 48 89 D6 48 89 CF 83 79 ?? 00 74"];

        join_all(patterns.iter().map(|p| scan(ctx, Pattern::new(p).unwrap())))
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
    };

    let string = async {
        // Locates either variant by searching for a string ref and finding the first function
        // call directly above it. Which variant depends on how much inlining has occured
        let s = Pattern::from_bytes(
            "  DrivingBone: %s\nDrivenParamet"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        )
        .unwrap();
        let strings = scan(ctx, s).await;

        let refs = join_all(
            strings
                .iter()
                .map(|s| scan(ctx, Pattern::new(format!("48 8d 15 X0x{s:x}")).unwrap())),
        )
        .await;

        let fn_gather_debug_data = ensure_one(
            refs.into_iter()
                .flatten()
                .map(|r| -> Result<_> {
                    Ok(ctx.image().get_root_function(r)?.map(|f| f.range.start..r))
                })
                .collect::<Result<Vec<_>>>()? // TODO avoid this collect?
                .into_iter()
                .flatten(),
        )?;

        let bytes = ctx.image().memory.range(fn_gather_debug_data.clone())?;

        let mut decoder = Decoder::with_ip(
            64,
            bytes,
            fn_gather_debug_data.start as u64,
            DecoderOptions::NONE,
        );

        let addr = decoder
            .iter()
            .filter_map(|i| (i.code() == Code::Call_rel32_64).then_some(i.memory_displacement64()))
            .last()
            .context("did not find CALL instruction")?;

        Ok::<_, ResolveError>(addr)
    };

    let any = join!(
        ctx.resolve(FNameToStringFString::resolver()),
        ctx.resolve(FNameToStringVoid::resolver()),
        string,
        patterns,
    );

    // use pattern if found
    if !any.3.is_empty() {
        return Ok(Self(ensure_one(any.3)?));
    }

    Ok(Self(any.0.map(|r| r.0).or(any.1.map(|r| r.0)).or(any.2)?))
});

/// public: class FString __cdecl FName::ToString(void) const
pub use super::models::fname::FNameToStringVoid;
impl_resolver_singleton!(all, FNameToStringVoid, |ctx| async {
    let patterns = [
        "E8 | ?? ?? ?? ?? ?? 01 00 00 00 ?? 39 ?? 48 0F 8E",
        "E8 | ?? ?? ?? ?? BD 01 00 00 00 41 39 6E ?? 0F 8E",
        "E8 | ?? ?? ?? ?? 48 8B 4C 24 ?? 8B FD 48 85 C9",
    ];

    BinaryMatcher::patterns(patterns)?
        .rip4()
        .ensure_one()
        .map(Self)
        .resolve(ctx)
        .await
});

/// public: void __cdecl FName::ToString(class FString &) const
pub use super::models::fname::FNameToStringFString;
impl_resolver_singleton!(all, FNameToStringFString, |ctx| async {
    let patterns =
        ["48 8b 48 ?? 48 89 4c 24 ?? 48 8d 4c 24 ?? e8 | ?? ?? ?? ?? 83 7c 24 ?? 00 48 8d"];

    BinaryMatcher::patterns(patterns)?
        .rip4()
        .ensure_one()
        .map(Self)
        .resolve(ctx)
        .await
});

/// FNamePool: resolved address of the global FName storage.
///
/// On UE 4.23+ this is the FNamePool struct's static address. On pre-4.23
/// this is the address of the static pointer to
/// `TStaticIndirectArrayThreadSafeRead<FNameEntry>` (i.e. `&GNames`).
/// Consumers branch on the engine version to interpret the value correctly.
pub use super::models::fname::FNamePool;
impl_resolver_singleton!(all, FNamePool, |ctx| async {
    use futures::join;
    use std::collections::HashSet;

    // post-4.23 FNamePool::FNamePool
    let post = async {
        let body = async {
            let body_matches: Vec<u64> = join_all([
                scan(ctx, Pattern::new("4? 89 ?? 08 41 b8 00 00 01 00").unwrap()),
                scan(ctx, Pattern::new("4? 8d 4? 08 41 b8 08 00 01 00").unwrap()),
            ])
            .await
            .into_iter()
            .flatten()
            .collect();
            let body_fns: HashSet<u64> = util::root_functions(ctx, &body_matches)?
                .into_iter()
                .collect();

            let caller_sites: Vec<u64> = join_all(body_fns.iter().flat_map(|f| {
                [
                    scan(ctx, Pattern::new(format!("e8 X0x{f:X}")).unwrap()),
                    scan(ctx, Pattern::new(format!("e9 X0x{f:X}")).unwrap()),
                ]
            }))
            .await
            .into_iter()
            .flatten()
            .collect();
            let caller_fns: HashSet<u64> = util::root_functions(ctx, &caller_sites)?
                .into_iter()
                .collect();

            Ok::<HashSet<u64>, ResolveError>(body_fns.union(&caller_fns).copied().collect())
        };

        let strings = async {
            let strs = [
                "\0ByteProperty\0",
                "\0IntProperty\0",
                "\0BoolProperty\0",
                "\0FloatProperty\0",
            ];
            let str_addrs: Vec<Vec<u64>> =
                join_all(strs.iter().map(|s| scan(ctx, util::utf8_pattern(s))))
                    .await
                    .into_iter()
                    .map(|matches| matches.into_iter().map(|a| a + 1).collect())
                    .collect();
            let xrefs: Vec<Vec<u64>> =
                join_all(str_addrs.iter().map(|addrs| util::scan_xrefs(ctx, addrs))).await;
            let fn_groups: Vec<HashSet<u64>> = xrefs
                .iter()
                .map(|rs| util::root_functions(ctx, rs).map(|fs| fs.into_iter().collect()))
                .collect::<Result<_>>()?;
            Ok::<HashSet<u64>, ResolveError>(
                fn_groups
                    .into_iter()
                    .reduce(|a, b| a.intersection(&b).copied().collect())
                    .unwrap_or_default(),
            )
        };

        let (body_set, str_set) = join!(body, strings);
        let mut candidates = body_set?;
        candidates.extend(str_set?);

        let shapes = [
            "48 8d 0d [ ?? ?? ?? ?? ] e8 [ ?? ?? ?? ?? ] c6 05 ?? ?? ?? ?? 01",
            "48 8d 0d [ ?? ?? ?? ?? ] e8 [ ?? ?? ?? ?? ] ?? ?? ?? c6 05 ?? ?? ?? ?? 01",
        ];
        let pool_matches = join_all(
            shapes
                .iter()
                .map(|s| scan_tagged(ctx, (), Pattern::new(s).unwrap())),
        )
        .await;

        let mut pool_addrs: HashSet<u64> = HashSet::new();
        for (_, pattern, addresses) in &pool_matches {
            for a in addresses {
                let Some(caps) = ctx.image().memory.captures(pattern, *a)? else {
                    continue;
                };
                if candidates.contains(&caps[1].rip()) {
                    pool_addrs.insert(caps[0].rip());
                }
            }
        }
        ensure_one(pool_addrs)
    };

    // pre-4.23 GNames getter
    let gnames = async {
        BinaryMatcher::patterns([
            "48 83 EC 28 48 8B 05 | ?? ?? ?? ?? 48 85 C0 75 ?? B9 08 04 00 00",
            "48 83 EC 28 48 8B 05 | ?? ?? ?? ?? 48 85 C0 75 ?? B9 08 08 00 00",
        ])?
        .rip4()
        .ensure_one()
        .resolve(ctx)
        .await
    };

    let (post_result, gnames_result) = join!(post, gnames);
    Ok(Self(post_result.or(gnames_result)?))
});

/// StaticFNameConst
pub use super::models::fname::StaticFNameConst;
impl_resolver_singleton!(all, StaticFNameConst, |ctx| async {
    BinaryMatcher::patterns([
        util::utf16_pattern("GLSL_ES3_1_ANDROID\0"),
        util::utf8_pattern("GLSL_ES3_1_ANDROID\0"),
    ])?
    .ensure_one()
    .try_flat_map(|str_addr| {
        BinaryMatcher::patterns([
            // pre-5.7 FName(.., FNAME_Add)
            format!("41 b8 01 00 00 00 48 8d 15 X0x{str_addr:08x} 48 8d 0d | ?? ?? ?? ?? e9"),
            // 5.7+ FName(..)
            format!("48 8d 15 X0x{str_addr:08x} 48 8d 0d | ?? ?? ?? ?? e9"),
        ])
    })
    .first()
    .rip4()
    .map(Self)
    .resolve(ctx)
    .await
});
