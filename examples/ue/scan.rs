//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/mod.rs#L582-L601>

use binary_bloodhound::{BinaryMatcher, IntoPattern};
use patternsleuth::{resolvers::AsyncContext, scanner::Pattern};

// Preserve the native scanner's address-only return shape for legacy heuristics.
pub(super) async fn scan(ctx: &AsyncContext<'_>, pattern: Pattern) -> Vec<u64> {
    scan_patterns(ctx, [pattern]).await
}

pub(super) async fn scan_patterns<P: IntoPattern>(
    ctx: &AsyncContext<'_>,
    patterns: impl IntoIterator<Item = P>,
) -> Vec<u64> {
    BinaryMatcher::patterns(patterns)
        .expect("valid scan patterns")
        .resolve(ctx)
        .await
        .expect("pattern scan")
        .into_iter()
        .map(|node| *node.value)
        .collect()
}
