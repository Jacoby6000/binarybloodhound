//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/kismet.rs>

use binary_bloodhound::{BinaryMatcher, Matcher};
use futures::future::join_all;
use iced_x86::{Decoder, DecoderOptions, Instruction};
#[cfg(feature = "image-pe")]
use patternsleuth::resolvers::ensure_one;

use patternsleuth::{
    MemoryTrait,
    image::Image,
    resolvers::{Result, bail_out, impl_resolver, impl_resolver_singleton},
};

fn find_instruction_displacement(
    image: &Image<'_>,
    address: u64,
    limit: usize,
    matches: impl Fn(&Instruction) -> bool,
) -> Result<Option<u64>> {
    let bytes = image.memory.range_from(address..)?;
    let mut decoder = Decoder::with_ip(
        64,
        &bytes[..bytes.len().min(limit)],
        address,
        DecoderOptions::NONE,
    );
    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        if matches(&instruction) {
            return Ok(Some(instruction.memory_displacement64()));
        }
    }
    Ok(None)
}

/// public: void __cdecl UObject::SkipFunction(struct FFrame &, void *const, class UFunction *)
pub use super::models::kismet::UObjectSkipFunction;
impl_resolver_singleton!(all, UObjectSkipFunction, |ctx| async {
    let patterns = [
        "40 55 41 54 41 55 41 56 41 57 48 83 EC 30 48 8D 6C 24 20 48 89 5D 40 48 89 75 48 48 89 7D 50 48 8B 05 ?? ?? ?? ?? 48 33 C5 48 89 45 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 4D 8B ?? ?? 8B ?? 85 ?? 75 05 41 8B FC EB ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? E0",
        "40 55 41 54 41 55 41 56 41 57 48 83 EC ?? 48 8D 6C 24 ?? 48 89 5D 40 48 89 75 48 48 89 7D 50 48 8B 05 ?? ?? ?? ?? 48 33 C5 48 89 45 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 05 41 8B FC EB",
        "40 55 53 56 57 41 54 41 55 41 56 41 57 48 83 EC ?? 48 8D 6C 24 ?? 48 8B 05 ?? ?? ?? ?? 48 33 C5 48 89 45 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 75 05 41 8B FC EB",
        // linux
        "55 01001??? 89 e5 01000??? 57 01000??? 56 01000??? 55 01000??? 54 53 50 01001??? 89 cf 01001??? 89 d6 01001??? 89 f3 01001??? 63 51 58 01001??? 85 d2 74 ??  01001??? 63 67 5c 01001??? 83 fc 10 7f ?? 01001??? 89 e4 01001??? 8d 42 1e 01001??? 83 e0 f0 01001??? 29 c4 01001??? 89 e4 eb ??",
    ];

    BinaryMatcher::patterns(patterns)?
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

// GNatives
pub use super::models::kismet::GNatives;
impl_resolver_singleton!(collect, GNatives);

impl_resolver_singleton!(PEImage, GNatives, |ctx| async {
    use futures::join;
    let (patterns, via_skip, via_step) = join!(
        ctx.resolve(GNativesPatterns::resolver()),
        ctx.resolve(GNativesViaSkipFunction::resolver()),
        ctx.resolve(GNativesViaFFrameStep::resolver()),
    );

    Ok(Self(ensure_one(
        [
            patterns.map(|r| r.0),
            via_skip.map(|r| r.0),
            via_step.map(|r| r.0),
        ]
        .into_iter()
        .filter_map(Result::ok),
    )?))
});

impl_resolver_singleton!(ElfImage, GNatives, |ctx| async {
    // On Linux, only use skip function approach
    ctx.resolve(GNativesViaSkipFunction::resolver())
        .await
        .map(|r| Self(r.0))
});

pub use super::models::kismet::GNativesPatterns;
impl_resolver_singleton!(collect, GNativesPatterns);

impl_resolver_singleton!(PEImage, GNativesPatterns, |ctx| async {
    let patterns = [
        "80 3D ?? ?? ?? ?? 00 48 8D 15 ?? ?? ?? ?? 75 ?? C6 05 ?? ?? ?? ?? 01 48 8D 05 | ?? ?? ?? ?? B9",
    ];

    BinaryMatcher::patterns(patterns)?
        .rip4()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

impl_resolver_singleton!(ElfImage, GNativesPatterns, |_ctx| async {
    bail_out!("GNativesPatterns not implemented for Linux");
});

// Skip-function-based resolver
pub use super::models::kismet::GNativesViaSkipFunction;
impl_resolver_singleton!(collect, GNativesViaSkipFunction);

impl_resolver_singleton!(PEImage, GNativesViaSkipFunction, |ctx| async {
    use iced_x86::{Code, Register};

    let skip_function = ctx.resolve(UObjectSkipFunction::resolver()).await?;
    // TODO recursive decode candidate
    if let Some(address) =
        find_instruction_displacement(ctx.image(), skip_function.0, 500, |inst| {
            inst.code() == Code::Lea_r64_m && inst.memory_base() == Register::RIP
        })?
    {
        return Ok(Self(address));
    }

    bail_out!("failed to find LEA instruction");
});

impl_resolver_singleton!(ElfImage, GNativesViaSkipFunction, |ctx| async {
    let skip_function = ctx.resolve(UObjectSkipFunction::resolver()).await?;
    if let Some(address) =
        find_instruction_displacement(ctx.image(), skip_function.0, 500, |inst| {
            inst.is_call_near_indirect() && inst.memory_index_scale() == 8
        })?
    {
        return Ok(Self(address));
    }

    bail_out!("failed to find call instruction");
});

// FFrame::Step-based resolver
pub use super::models::kismet::GNativesViaFFrameStep;
impl_resolver_singleton!(collect, GNativesViaFFrameStep);

impl_resolver_singleton!(PEImage, GNativesViaFFrameStep, |ctx| async {
    use iced_x86::{Code, Register};

    let step = ctx.resolve(FFrameStep::resolver()).await?;
    if let Some(address) = find_instruction_displacement(ctx.image(), step.0, 0x40, |inst| {
        inst.code() == Code::Lea_r64_m && inst.memory_base() == Register::RIP
    })? {
        return Ok(Self(address));
    }

    bail_out!("failed to find LEA instruction");
});

impl_resolver_singleton!(ElfImage, GNativesViaFFrameStep, |_ctx| async {
    bail_out!("GNativesViaFFrameStep not implemented for Linux");
});

/// public: void __cdecl FFrame::Step(class UObject *, void *const)
pub use super::models::kismet::FFrameStep;
impl_resolver_singleton!(all, FFrameStep, |ctx| async {
    let patterns = [
        "48 8B 41 20 4C 8B D2 48 8B D1 44 0F B6 08 48 FF C0 48 89 41 20 41 8B C1 4C 8D 0D ?? ?? ?? ?? 49 8B CA 49 FF 24 C1",
        // linux
        "01001??? 89 f8 01001??? 8b 4f 20 01001??? 8d 79 01 01001??? 89 78 20 0f b6 09 01001??? 8b 0c ?????101 ?? ?? ?? ?? 01001??? 89 f7 01001??? 89 c6 ff e1",
    ];

    BinaryMatcher::patterns(patterns)?
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

/// public: void __cdecl FFrame::StepExplicitProperty(void *const, class FProperty *)
/// public: void __cdecl FFrame::StepExplicitProperty(void *const, class UProperty *)
pub use super::models::kismet::FFrameStepExplicitProperty;
impl_resolver_singleton!(all, FFrameStepExplicitProperty, |ctx| async {
    let patterns = [
        "41 8B 40 40 4D 8B C8 4C 8B D1 48 0F BA E0 08 73 ?? 48 8B ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? 00 48 8B 40 10 4C 39 08 75 F7 48 8B 48 08 49 89 4A 38 ?? ?? ?? 40 ?? ?? ?? ?? ?? 4C ?? 41 ?? 49",
        "48 89 5C 24 ?? 48 89 ?? 24 ?? 57 48 83 EC 20 41 8B 40 40 49 8B D8 48 8B ?? 48 8B F9 48 0F BA E0 08 73 ?? 48 8B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8B 40 10 48 39 18 75 F7 48 8B ?? 08 48 89 ?? 38 48",
        // linux
        "41 57 41 56 53 48 89 d3 49 89 ff f6 42 41 01 75 ?? 01001??? 89 f6 01001??? 8b 47 28 01001??? 63 4b 4c 01001??? 01 c1 01001??? 89 4f 38 01001??? 89 47 40 01001??? 8b 03 01001??? 89 df ff 90 88 00 00 00 84 c0 74 ?? 01001??? 8b 43 08 b9 00 00 00 24 23 48 10 01001??? 8b 7f 40 81 f9 00 00 00 04",
    ];

    BinaryMatcher::patterns(patterns)?
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

/// public: static void __cdecl UKismetStringLibrary::execLen(class UObject *, struct FFrame &, void *const)
/// public: void __cdecl UKismetStringLibrary::execLen(struct FFrame &, void *const)
pub use super::models::kismet::FFrameStepViaExec;
impl_resolver!(all, FFrameStepViaExec, |ctx| async {
    let patterns = [
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ?? 33 FF 33 C0 49 8B F0 48 8B DA 48 8B CA 48 89 7C 24 20 48 89 7C 24 28 48 39 42 20 74 10 48 8B 52 18 4C 8D 44 24 20 E8 [ ?? ?? ?? ?? ] EB 1C 4C 8B 82 80 00 00 00 49 8B 40 ?? 48 89 82 80 00 00 00 48 8D 54 24 20 E8 [ ?? ?? ?? ?? ] 48 8B 43 20 48 8D 4C 24 20 48 85 C0",
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ?? 33 FF 49 8B F0 48 8B DA 48 89 7C 24 20 48 ?? ?? ?? ?? ?? ?? ?? 48 39 7A 20 74 10 48 8B 52 18 4C 8D 44 24 20 E8 [ ?? ?? ?? ?? ] EB 1C 4C 8B 82 80 00 00 00 49 8B 40 ?? 48 89 82 80 00 00 00 48 8D 54 24 20 E8 [ ?? ?? ?? ?? ] 48 8B 43 20 48 8D 4C 24 20 48 85 C0 40 0F",
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 33 ?? 49 8B F0 48 89 ?? 24 20 48 8B ?? 48 89 ?? 24 28 E8 [ ?? ?? ?? ?? ] 48 8B ?? 48 39 ?? 20 74 10 48 8B ?? 18 4C 8D 44 24 20 E8 ?? ?? ?? ?? EB 1C 4C 8B ?? ?? 00 00 00 48 8D 54 24 20 49 8B 40 20 48 89 ?? ?? 00 00 00 E8 [ ?? ?? ?? ?? ] 48 8B ?? 20 48",
        "41 56 53 01001??? 83 ec 18 01001??? 89 d6 01001??? 89 f3 0f 57 c0 0f 29 04 ??100??? e8 ?? ?? ?? ?? 01001??? 83 7b 20 00 74 ?? 01001??? 8b 73 18 01001??? 89 e2 01001??? 89 df e8 [ ?? ?? ?? ?? ] eb ?? 01001??? 8b 93 88 00 00 00 01001??? 8b 42 20 01001??? 89 83 88 00 00 00 01001??? 89 e6 01001??? 89 df e8 [ ?? ?? ?? ?? ]",
    ];

    let context: &patternsleuth::resolvers::AsyncContext<'_> = ctx;
    let results = join_all(patterns.into_iter().map(|pattern| async move {
        BinaryMatcher::capture_patterns([pattern])?
            .try_map(|node| Ok((node.captures[0].rip4()?, node.captures[1].rip4()?)))
            .ensure_one()
            .resolve(context)
            .await
    }))
    .await;

    // Upstream discards failed or ambiguous signatures before comparing successes.
    Matcher::from_nodes(
        results
            .into_iter()
            .filter_map(Result::ok)
            .collect::<Vec<_>>(),
    )
    .ensure_one()
    .resolve(ctx)
    .await
    .map(|node| Self {
        step: node.value.0,
        step_explicit_property: node.value.1,
    })
});

#[cfg(test)]
mod tests {
    use super::find_instruction_displacement;
    use iced_x86::{Code, Register};

    fn lea(inst: &iced_x86::Instruction) -> bool {
        inst.code() == Code::Lea_r64_m && inst.memory_base() == Register::RIP
    }

    #[test]
    fn native_decoder_keeps_first_match_without_function_metadata() {
        let image = super::super::tests::image(vec![
            0x48, 0x8d, 0x05, 0x10, 0, 0, 0, 0x48, 0x8d, 0x05, 0x20, 0, 0, 0,
        ]);

        assert_eq!(
            find_instruction_displacement(&image, 0x1000, 500, lea).unwrap(),
            Some(0x1017)
        );
    }

    #[test]
    fn native_decoder_respects_byte_limit_including_partial_instructions() {
        let image = super::super::tests::image(vec![0x90, 0x48, 0x8d, 0x05, 0x10, 0, 0, 0]);

        for limit in [0, 1, 7] {
            assert_eq!(
                find_instruction_displacement(&image, 0x1000, limit, lea).unwrap(),
                None
            );
        }
        assert_eq!(
            find_instruction_displacement(&image, 0x1000, 8, lea).unwrap(),
            Some(0x1018)
        );
    }

    #[test]
    fn native_decoder_propagates_unmapped_start() {
        let image = super::super::tests::image(vec![]);
        assert!(find_instruction_displacement(&image, 0x2000, 500, lea).is_err());
    }

    #[test]
    fn native_decoder_retains_scaled_indirect_call_predicate() {
        let image = super::super::tests::image(vec![
            0xff, 0x14, 0x85, 0x10, 0x20, 0, 0, 0xff, 0x14, 0xc5, 0x30, 0x20, 0, 0,
        ]);

        assert_eq!(
            find_instruction_displacement(&image, 0x1000, 500, |inst| {
                inst.is_call_near_indirect() && inst.memory_index_scale() == 8
            })
            .unwrap(),
            Some(0x2030)
        );
    }
}
