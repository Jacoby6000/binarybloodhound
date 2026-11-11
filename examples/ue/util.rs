//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/mod.rs#L34-L251>

use binary_bloodhound::BinaryMatcher;
use patternsleuth::resolvers::AsyncContext;

pub use patternsleuth::resolvers::unreal::util::{
    find_calls, root_functions, utf8_pattern, utf16, utf16_pattern,
};

pub async fn string_pattern(ctx: &AsyncContext<'_>, string: &str) -> Vec<u64> {
    BinaryMatcher::patterns([utf16_pattern(string), utf8_pattern(string)])
        .expect("literal patterns")
        .resolve(ctx)
        .await
        .expect("pattern scan")
}

pub async fn scan_xrefs(
    ctx: &AsyncContext<'_>,
    addresses: impl IntoIterator<Item = &u64>,
) -> Vec<u64> {
    let addresses: Vec<_> = addresses.into_iter().copied().collect();
    BinaryMatcher::candidates(addresses)
        .references()
        .addresses()
        .resolve(ctx)
        .await
        .expect("reference scan")
}

pub async fn scan_xcalls(
    ctx: &AsyncContext<'_>,
    addresses: impl IntoIterator<Item = &u64>,
) -> Vec<u64> {
    let addresses: Vec<_> = addresses.into_iter().copied().collect();
    BinaryMatcher::candidates(addresses)
        .callers()
        .addresses()
        .resolve(ctx)
        .await
        .expect("caller scan")
}
