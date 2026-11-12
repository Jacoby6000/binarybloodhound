//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/game_loop.rs>

use binary_bloodhound::BinaryMatcher;
#[cfg(feature = "image-pe")]
use {
    binary_bloodhound::Matcher,
    futures::future::join_all,
    std::{
        cmp::Reverse,
        collections::{HashMap, HashSet},
    },
};

use super::util;
use patternsleuth::resolvers::{bail_out, impl_resolver_singleton};

pub use super::models::engine::Main;
impl_resolver_singleton!(collect, Main);
impl_resolver_singleton!(PEImage, Main, |ctx| async {
    BinaryMatcher::pattern(util::utf16_pattern("UnrealEngine4\0"))
        .references()
        .root_functions()
        .addresses()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});
impl_resolver_singleton!(ElfImage, Main, |_ctx| async {
    bail_out!("ElfImage unimplemented");
});

pub use super::models::engine::FEngineLoopTick;
impl_resolver_singleton!(collect, FEngineLoopTick);
impl_resolver_singleton!(PEImage, FEngineLoopTick, |ctx| async {
    // intersect the always-present anchor with each secondary and union the results
    let primary = "t.IdleWhenNotForeground\0";
    let secondaries = ["r.OneFrameThreadLag\0", "FEngineLoop::Tick.Benchmarking\0"];

    let primary_fns = BinaryMatcher::pattern(util::utf16_pattern(primary))
        .references()
        .root_functions()
        .addresses()
        .resolve(ctx)
        .await?;

    let secondary_fns: Vec<Vec<_>> = join_all(secondaries.map(|s| async move {
        BinaryMatcher::pattern(util::utf16_pattern(s))
            .references()
            .root_functions()
            .addresses()
            .resolve(ctx)
            .await
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    // Reuse the resolved primary candidates; do not rescan the anchor per branch.
    let primary = Matcher::from_nodes(primary_fns);
    let branches = secondary_fns
        .into_iter()
        .map(|secondary| primary.clone().intersect(Matcher::from_nodes(secondary)));
    Matcher::union_all(branches)
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});
impl_resolver_singleton!(ElfImage, FEngineLoopTick, |_ctx| async {
    bail_out!("ElfImage unimplemented");
});

pub use super::models::engine::UGameEngineTick;
impl_resolver_singleton!(all, UGameEngineTick, |ctx| async {
    BinaryMatcher::patterns(["causeevent=\0", "CAUSEEVENT \0"].map(util::utf16_pattern))?
        .references()
        .root_functions()
        .addresses()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

/// int32_t FEngineLoop::Init(class FEngineLoop* this)
pub use super::models::engine::FEngineLoopInit;
impl_resolver_singleton!(collect, FEngineLoopInit);

impl_resolver_singleton!(PEImage, FEngineLoopInit, |ctx| async {
    let search_strings = [
        "FEngineLoop::Init\0",
        "Failed to load UnrealEd Engine class '%s'.",
        "One or more modules failed PostEngineInit",
    ];
    BinaryMatcher::patterns(search_strings.map(util::utf16_pattern))?
        .references()
        .root_functions()
        .addresses()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

impl_resolver_singleton!(ElfImage, FEngineLoopInit, |ctx| async {
    let search_strings = [
        util::utf8_pattern("FEngineLoop::Init\0"),
        // The UnrealEd error belongs to a separate function on ELF.
        util::utf16_pattern("One or more modules failed PostEngineInit"),
    ];
    BinaryMatcher::patterns(search_strings)?
        .references()
        .root_functions()
        .addresses()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

/// void UWorld::Tick(ELevelTick TickType, float DeltaSeconds)
pub use super::models::engine::UWorldTick;
impl_resolver_singleton!(collect, UWorldTick);

#[cfg(feature = "image-pe")]
struct WorldTickCandidate {
    anchors: HashSet<usize>,
    size: u64,
}

#[cfg(feature = "image-pe")]
fn select_world_tick(
    candidates: HashMap<u64, WorldTickCandidate>,
    n_specific: usize,
) -> patternsleuth::resolvers::Result<u64> {
    // Rank by specific anchors, total anchors, generic anchors, then span.
    let mut ranked: Vec<_> = candidates
        .into_iter()
        .map(|(address, candidate)| {
            let total = candidate.anchors.len();
            let specific = candidate
                .anchors
                .iter()
                .filter(|&&index| index < n_specific)
                .count();
            ((specific, total, total - specific, candidate.size), address)
        })
        .collect();
    ranked.sort_by_key(|(score, _)| Reverse(*score));
    let Some(&(score, address)) = ranked.first() else {
        bail_out!("no UWorld::Tick anchor string referenced inside a function");
    };
    let (specific, total, _, size) = score;
    if specific == 0 && (total < 2 || size < 0x800) {
        bail_out!("only generic net anchors on a small fn");
    }
    if ranked.get(1).is_some_and(|(other, _)| *other == score) {
        bail_out!("ambiguous UWorld::Tick candidates");
    }
    Ok(address)
}

impl_resolver_singleton!(PEImage, UWorldTick, |ctx| async {
    const UWORLD_TICK_SPECIFIC: &[&str] = &[
        "TickInGamePerfTrackersRT\0",
        "UWorld_Tick\0",
        "%d PAWN SPAWNS THIS FRAME! \0",
        "World Tick Time\0",
        "Tick Time\0",
        "GT Tickable Time\0",
        "Net Tick Time\0",
        "Nav Tick Time\0",
        "Update Camera Time\0",
        "Finish Async Trace Time\0",
        "Reset Async Trace Time\0",
        "Net Broadcast Tick Time\0",
        "TickGroups\0",
    ];

    const UWORLD_TICK_GENERIC: &[&str] = &[
        "Your connection to the host has been lost.\0",
        "ConnectionFailed\0",
        "Media\0",
    ];

    let n_specific = UWORLD_TICK_SPECIFIC.len();

    BinaryMatcher::tagged_capture_patterns(
        UWORLD_TICK_SPECIFIC
            .iter()
            .chain(UWORLD_TICK_GENERIC.iter())
            .enumerate()
            .map(|(index, text)| (index, util::utf16_pattern(text))),
    )?
    .references()
    .root_functions()
    .try_transform(move |nodes| {
        let mut candidates = HashMap::new();
        for node in nodes {
            let function = node.value.as_ref();
            let anchor = *node.parent().parent().tag;
            let candidate =
                candidates
                    .entry(function.start)
                    .or_insert_with(|| WorldTickCandidate {
                        anchors: HashSet::new(),
                        size: function.size(),
                    });
            candidate.anchors.insert(anchor);
        }
        select_world_tick(candidates, n_specific)
    })
    .resolve(ctx)
    .await
    .map(|node| Self(*node.value))
});
impl_resolver_singleton!(ElfImage, UWorldTick, |_ctx| async {
    bail_out!("ElfImage unimplemented");
});

#[cfg(all(test, feature = "image-pe"))]
mod tests {
    use super::{WorldTickCandidate, select_world_tick};

    fn candidate(anchors: &[usize], size: u64) -> WorldTickCandidate {
        WorldTickCandidate {
            anchors: anchors.iter().copied().collect(),
            size,
        }
    }

    #[test]
    fn world_tick_prefers_specific_anchors_over_generic_count_and_size() {
        let candidates = [
            (0x1000, candidate(&[0], 0x100)),
            (0x2000, candidate(&[2, 3, 4], 0x1000)),
        ]
        .into();

        assert_eq!(select_world_tick(candidates, 2).unwrap(), 0x1000);
    }

    #[test]
    fn world_tick_ranks_total_anchors_before_function_size() {
        let candidates = [
            (0x1000, candidate(&[0, 2], 0x100)),
            (0x2000, candidate(&[0], 0x1000)),
        ]
        .into();

        assert_eq!(select_world_tick(candidates, 2).unwrap(), 0x1000);
    }

    #[test]
    fn world_tick_uses_size_to_break_equal_anchor_scores() {
        let candidates = [
            (0x1000, candidate(&[0], 0x100)),
            (0x2000, candidate(&[0], 0x200)),
        ]
        .into();

        assert_eq!(select_world_tick(candidates, 2).unwrap(), 0x2000);
    }

    #[test]
    fn world_tick_accepts_generic_anchors_only_at_both_thresholds() {
        for (anchors, size, accepted) in [
            (&[2, 3][..], 0x800, true),
            (&[2, 3], 0x7ff, false),
            (&[2], 0x1000, false),
        ] {
            let candidates = [(0x1000, candidate(anchors, size))].into();
            let result = select_world_tick(candidates, 2);

            if accepted {
                assert_eq!(result.unwrap(), 0x1000);
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "only generic net anchors on a small fn"
                );
            }
        }
    }

    #[test]
    fn world_tick_rejects_equal_best_scores() {
        let candidates = [
            (0x1000, candidate(&[0], 0x100)),
            (0x2000, candidate(&[1], 0x100)),
        ]
        .into();
        let error = select_world_tick(candidates, 2).unwrap_err();

        assert_eq!(error.to_string(), "ambiguous UWorld::Tick candidates");
    }

    #[test]
    fn world_tick_rejects_missing_candidates() {
        let error = select_world_tick(Default::default(), 2).unwrap_err();

        assert_eq!(
            error.to_string(),
            "no UWorld::Tick anchor string referenced inside a function"
        );
    }
}
