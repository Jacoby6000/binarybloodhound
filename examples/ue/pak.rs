//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/pak.rs>

use std::fmt::Debug;

use patternsleuth::resolvers::impl_resolver_singleton;

#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct FPakPlatformFileInitialize(pub u64);
impl_resolver_singleton!(collect, FPakPlatformFileInitialize);
impl_resolver_singleton!(PEImage, FPakPlatformFileInitialize, |ctx| async {
    use super::util;
    use binary_bloodhound::BinaryMatcher;
    use patternsleuth::resolvers::ensure_one;
    let string_xrefs = |strings: &'static [&'static str]| async {
        BinaryMatcher::patterns(strings.iter().map(|s| util::utf16_pattern(s)))?
            .references()
            .root_functions()
            .addresses()
            .try_map(ensure_one)
            .resolve(ctx)
            .await
    };

    let (a, b) = futures::join!(
        string_xrefs(&["%sPaks/%s-\0"]),
        string_xrefs(&[
            "ushaderbytecode\0",
            "%sPaks/global\0",
            "fileopenlog\0",
            "Signedpak\0"
        ]),
    );
    Ok(Self(b.or(a)?))
});
impl_resolver_singleton!(ElfImage, FPakPlatformFileInitialize, |_ctx| async {
    patternsleuth::resolvers::bail_out!("ElfImage unimplemented");
});
