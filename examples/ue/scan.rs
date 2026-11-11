//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/mod.rs#L582-L601>

use binary_bloodhound::BinaryMatcher;
use patternsleuth::{resolvers::AsyncContext, scanner::Pattern};

// Pattern sources cannot return resolver errors; keep the upstream scan shape for
// heuristics that inspect captures or tag matches before choosing a candidate.
pub(super) async fn scan(ctx: &AsyncContext<'_>, pattern: Pattern) -> Vec<u64> {
    BinaryMatcher::pattern(pattern)
        .resolve(ctx)
        .await
        .expect("pattern scan")
        .into_iter()
        .map(|node| *node.value)
        .collect()
}

pub(super) async fn scan_tagged<T>(
    ctx: &AsyncContext<'_>,
    tag: T,
    pattern: Pattern,
) -> (T, Pattern, Vec<u64>) {
    let matches = scan(ctx, pattern.clone()).await;
    (tag, pattern, matches)
}

#[cfg(any(feature = "image-pe", test))]
pub(super) async fn scan_tagged2<T: Copy>(
    ctx: &AsyncContext<'_>,
    tag: T,
    pattern: Pattern,
) -> Vec<(T, u64)> {
    scan(ctx, pattern)
        .await
        .into_iter()
        .map(|address| (tag, address))
        .collect()
}
