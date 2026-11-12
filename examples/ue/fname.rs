//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/fname.rs>

#[cfg(feature = "image-elf")]
use super::scan::scan;
use binary_bloodhound::{BinaryMatcher, Matcher};
#[cfg(feature = "image-elf")]
use futures::future::join_all;
#[cfg(feature = "image-elf")]
use patternsleuth::scanner::Pattern;

use super::util;
#[cfg(feature = "image-elf")]
use patternsleuth::MemoryTrait;
use patternsleuth::resolvers::ResolveError;
#[cfg(feature = "image-pe")]
use patternsleuth::resolvers::try_ensure_one;
use patternsleuth::resolvers::{ensure_one, impl_resolver_singleton};

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
    use super::scan::scan_patterns;
    use futures::join;
    use iced_x86::{Code, Decoder, DecoderOptions};
    use patternsleuth::{MemoryTrait, resolvers::Context};

    // FName(wchar_t const*, EFindName) prologue
    let ctor = scan_patterns(
        ctx,
        [
            "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 41 8B F8 33 C9 4C 8B DA 44 8B D1 4C 8B CA 48 85 D2 74 ?? 0F B7 02 66 85 C0",
            "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 48 89 54 24 20 33 C9 41 8B F8 4C 8B D2 44 8B C9 48 85 D2 74 ?? 0F B7 02 66 85 C0",
        ],
    );
    let strings = scan_patterns(
        ctx,
        ["TGPUSkinVertexFactoryUnlimited\0", "MovementComponent0\0"].map(util::utf16_pattern),
    );
    let patterns = scan_patterns(
        ctx,
        ["EB 07 48 8D 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 B8 01 00 00 00 E8 | ?? ?? ?? ??"],
    );
    let (ctor, patterns, strings) = join!(ctor, patterns, strings);

    // prefer the direct prologue match when present
    if !ctor.is_empty() {
        return BinaryMatcher::candidates(ctor)
            .ensure_one()
            .resolve(ctx)
            .await
            .map(|node| Self(*node.value));
    }

    // sometimes the call gets inlined so use patterns if any match
    if !patterns.is_empty() {
        return BinaryMatcher::candidates(patterns)
            .rip4()
            .ensure_one()
            .resolve(ctx)
            .await
            .map(|node| Self(*node.value));
    }

    enum Tag {
        Direct,
        FirstCall,
    }

    let refs = BinaryMatcher::tagged_capture_patterns(strings.into_iter().flat_map(|s| {
        [
            (
                Tag::FirstCall,
                format!("48 8d 15 X0x{s:x} 4c 8d 05 ?? ?? ?? ?? 41 b1 01 e8 [ ?? ?? ?? ?? ]"),
            ),
            (
                Tag::Direct,
                format!("48 8d 15 X0x{s:x} 48 8d 0d ?? ?? ?? ?? e8 [ ?? ?? ?? ?? ]"),
            ),
            (
                Tag::Direct,
                format!(
                    "41 b8 01 00 00 00 48 8d 15 X0x{s:x} 48 8d 0d ?? ?? ?? ?? e9 [ ?? ?? ?? ?? ]"
                ),
            ),
        ]
    }))?
    .resolve(ctx)
    .await?;

    // Keep thunk decoding lazy: native uniqueness checking can stop early.
    Ok(Self(try_ensure_one(refs.iter().map(|node| {
        let f = node.captures[0].rip4()?;
        match node.tag.as_ref() {
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
    }))?))
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
            let str_addr = *str_addr.value;
            BinaryMatcher::patterns([format!(
                "e8 | ?? ?? ?? ?? 49 8b 5f 10 48 8d 7c 24 30 be 0x{str_addr:08x}"
            )])
        })
        .rip4()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

impl_resolver_singleton!(PEImage, FNameToString, |ctx| async {
    use futures::join;
    use iced_x86::{Code, Decoder, DecoderOptions};
    use patternsleuth::{MemoryTrait, resolvers::Context};

    let patterns = BinaryMatcher::patterns(["56 57 48 83 EC 28 48 89 D6 48 89 CF 83 79 ?? 00 74"])?;
    let patterns = patterns.resolve(ctx);

    let string = async {
        // Locates either variant by searching for a string ref and finding the first function
        // call directly above it. Which variant depends on how much inlining has occured
        let ranges =
            BinaryMatcher::pattern(util::utf16_pattern("  DrivingBone: %s\nDrivenParamet"))
                .try_flat_map(|s| BinaryMatcher::patterns([format!("48 8d 15 X0x{:x}", *s.value)]))
                .with_context()
                .try_map_filter(|(ctx, r)| {
                    Ok(ctx
                        .image()
                        .get_root_function(*r.value)?
                        .map(|f| f.range.start..*r.value))
                })
                .resolve(ctx)
                .await?;
        // Finish every root lookup before native uniqueness checking.
        let fn_gather_debug_data =
            ensure_one(ranges.into_iter().map(|node| (*node.value).clone()))?;

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
    let patterns = any.3?;
    if !patterns.is_empty() {
        return Ok(Self(ensure_one(
            patterns.into_iter().map(|node| *node.value),
        )?));
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
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

/// public: void __cdecl FName::ToString(class FString &) const
pub use super::models::fname::FNameToStringFString;
impl_resolver_singleton!(all, FNameToStringFString, |ctx| async {
    let patterns =
        ["48 8b 48 ?? 48 89 4c 24 ?? 48 8d 4c 24 ?? e8 | ?? ?? ?? ?? 83 7c 24 ?? 00 48 8d"];

    BinaryMatcher::patterns(patterns)?
        .rip4()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
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
            let body_fns: HashSet<u64> = BinaryMatcher::patterns([
                "4? 89 ?? 08 41 b8 00 00 01 00",
                "4? 8d 4? 08 41 b8 08 00 01 00",
            ])?
            .root_functions()
            .addresses()
            .resolve(ctx)
            .await?
            .into_iter()
            .map(|node| *node.value)
            .collect();
            let caller_fns =
                BinaryMatcher::candidates(body_fns.iter().copied().collect::<Vec<_>>())
                    .callers()
                    .root_functions()
                    .addresses()
                    .resolve(ctx)
                    .await?
                    .into_iter()
                    .map(|node| *node.value);

            Ok::<HashSet<u64>, ResolveError>(body_fns.into_iter().chain(caller_fns).collect())
        };

        let strings = async {
            let nodes = Matcher::intersect_all(
                [
                    "\0ByteProperty\0",
                    "\0IntProperty\0",
                    "\0BoolProperty\0",
                    "\0FloatProperty\0",
                ]
                .map(|text| {
                    BinaryMatcher::pattern(util::utf8_pattern(text))
                        .offset(1)
                        .references()
                        .root_functions()
                        .addresses()
                }),
            )
            .resolve(ctx)
            .await?;
            Ok::<HashSet<u64>, ResolveError>(nodes.into_iter().map(|node| *node.value).collect())
        };

        let (body_set, str_set) = join!(body, strings);
        let mut candidates = body_set?;
        candidates.extend(str_set?);

        let shapes = [
            "48 8d 0d [ ?? ?? ?? ?? ] e8 [ ?? ?? ?? ?? ] c6 05 ?? ?? ?? ?? 01",
            "48 8d 0d [ ?? ?? ?? ?? ] e8 [ ?? ?? ?? ?? ] ?? ?? ?? c6 05 ?? ?? ?? ?? 01",
        ];
        BinaryMatcher::capture_patterns(shapes)?
            .try_map_filter(|node| {
                let caps = &node.captures;
                if candidates.contains(&caps[1].rip4()?) {
                    Ok(Some(caps[0].rip4()?))
                } else {
                    Ok(None)
                }
            })
            .ensure_one()
            .resolve(ctx)
            .await
            .map(|node| *node.value)
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
        .map(|node| *node.value)
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
        let str_addr = *str_addr.value;
        BinaryMatcher::patterns([
            // pre-5.7 FName(.., FNAME_Add)
            format!("41 b8 01 00 00 00 48 8d 15 X0x{str_addr:08x} 48 8d 0d | ?? ?? ?? ?? e9"),
            // 5.7+ FName(..)
            format!("48 8d 15 X0x{str_addr:08x} 48 8d 0d | ?? ?? ?? ?? e9"),
        ])
    })
    .first()
    .rip4()
    .resolve(ctx)
    .await
    .map(|node| Self(*node.value))
});

#[cfg(all(test, feature = "image-pe"))]
mod cleanup_tests {
    use super::*;
    use object::SectionKind;
    use patternsleuth::{
        NamedMemorySection,
        image::{Image, ImageType},
        scanner::Pattern,
    };

    fn image(bytes: Vec<u8>) -> Image<'static> {
        let image = super::super::tests::image(bytes);
        Image::from_memory(
            0x1000,
            image.memory,
            ImageType::PEImage(patternsleuth::image::pe::PEImage {
                exception_directory_range: 0x3000..0x300c,
                exception_children_cache: Default::default(),
            }),
        )
        .with_section(NamedMemorySection::new(
            ".pdata".into(),
            0x3000,
            SectionKind::ReadOnlyData,
            [0_u32, 0x80, 0x2100]
                .into_iter()
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
    fn to_string_string_pipeline_matches_native_last_call_and_pattern_priority() {
        for (references, patterns, expected) in [
            (0, 0, None),
            (1, 0, Some(0x1900)),
            (2, 0, None),
            (2, 1, Some(0x1200)),
            (1, 2, None),
        ] {
            let mut bytes = vec![0x90; 0x1000];
            let text = util::utf16("  DrivingBone: %s\nDrivenParamet");
            bytes[0x800..0x800 + text.len()].copy_from_slice(&text);
            relative(&mut bytes, 0, &[0xe8], 0x1800);
            relative(&mut bytes, 0x10, &[0xe8], 0x1900);
            for index in 0..references {
                relative(&mut bytes, 0x30 + index * 0x10, &[0x48, 0x8d, 0x15], 0x1800);
            }
            let pattern =
                Pattern::new("56 57 48 83 EC 28 48 89 D6 48 89 CF 83 79 ?? 00 74").unwrap();
            for index in 0..patterns {
                let start = 0x200 + index * 0x40;
                bytes[start..start + pattern.simple.sig.len()].copy_from_slice(&pattern.simple.sig);
            }
            let image = image(bytes);
            let result = image.resolve(FNameToString::resolver());
            let upstream =
                image.resolve(patternsleuth::resolvers::unreal::fname::FNameToString::resolver());

            assert_eq!(result.as_ref().ok().map(|value| value.0), expected);
            assert_eq!(
                result
                    .map(|value| value.0)
                    .map_err(|error| error.to_string()),
                upstream
                    .map(|value| value.0)
                    .map_err(|error| error.to_string())
            );
        }
    }
}
