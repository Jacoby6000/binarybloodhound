//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/game_loop.rs>

use binary_bloodhound::BinaryMatcher;
#[cfg(feature = "image-pe")]
use {
    super::scan::scan_tagged,
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
        .map(Self)
        .resolve(ctx)
        .await
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
    let primary = BinaryMatcher::candidates(primary_fns);
    let branches = secondary_fns.into_iter().map(|secondary| {
        primary
            .clone()
            .intersect(BinaryMatcher::candidates(secondary))
    });
    Matcher::union_all(branches)
        .ensure_one()
        .map(Self)
        .resolve(ctx)
        .await
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
        .map(Self)
        .resolve(ctx)
        .await
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
        .map(Self)
        .resolve(ctx)
        .await
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
        .map(Self)
        .resolve(ctx)
        .await
});

/// void UWorld::Tick(ELevelTick TickType, float DeltaSeconds)
pub use super::models::engine::UWorldTick;
impl_resolver_singleton!(collect, UWorldTick);
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

    let str_results = join_all(
        UWORLD_TICK_SPECIFIC
            .iter()
            .chain(UWORLD_TICK_GENERIC.iter())
            .enumerate()
            .map(|(i, s)| scan_tagged(ctx, i, util::utf16_pattern(s))),
    )
    .await;

    let xref_results = join_all(
        str_results
            .into_iter()
            .map(
                |(idx, _pattern, addrs)| async move { (idx, util::scan_xrefs(ctx, &addrs).await) },
            ),
    )
    .await;

    // bin each xref to its containing root function
    let mut fn_anchors: HashMap<u64, HashSet<usize>> = HashMap::new();
    let mut fn_size: HashMap<u64, u64> = HashMap::new();
    for (idx, refs) in xref_results {
        for r in refs {
            if let Some(f) = ctx.image().get_root_function(r)? {
                fn_anchors.entry(f.range.start).or_default().insert(idx);
                fn_size
                    .entry(f.range.start)
                    .or_insert(f.range.end - f.range.start);
            }
        }
    }
    if fn_anchors.is_empty() {
        bail_out!("no UWorld::Tick anchor string referenced inside a function");
    }

    // rank key: (#specific, #total, #generic, span), all descending.
    let score = |fn_addr: &u64| {
        let set = &fn_anchors[fn_addr];
        let spec = set.iter().filter(|&&i| i < n_specific).count();
        (spec, set.len(), set.len() - spec, fn_size[fn_addr])
    };

    let mut fns = fn_anchors.keys().copied().collect::<Vec<_>>();
    fns.sort_by_key(|f| Reverse(score(f)));
    let best = fns[0];
    let (best_spec, best_total, _best_gen, best_size) = score(&best);

    if best_spec == 0 && (best_total < 2 || best_size < 0x800) {
        bail_out!("only generic net anchors on a small fn");
    }

    // require a strict winner
    if fns.len() > 1 && score(&fns[1]) == score(&best) {
        bail_out!("ambiguous UWorld::Tick candidates");
    }

    Ok(UWorldTick(best))
});
impl_resolver_singleton!(ElfImage, UWorldTick, |_ctx| async {
    bail_out!("ElfImage unimplemented");
});
