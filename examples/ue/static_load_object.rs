//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/static_load_object.rs>

use binary_bloodhound::BinaryMatcher;
use futures::join;

use super::util;
use patternsleuth::resolvers::{ensure_one, impl_resolver_singleton};

/// class UObject * __cdecl StaticLoadObject(class UClass *, class UObject *, wchar_t const *, wchar_t const *, unsigned int, class UPackageMap *, bool, struct FLinkerInstancingContext const *)
pub use super::models::objects::StaticLoadObject;
impl_resolver_singleton!(all, StaticLoadObject, |ctx| async {
    let any = join!(
        ctx.resolve(StaticLoadObjectPatterns::resolver()),
        ctx.resolve(StaticLoadObjectString::resolver()),
    );

    Ok(Self(ensure_one(
        [any.0.map(|r| r.0), any.1.map(|r| r.0)]
            .into_iter()
            .filter_map(Result::ok),
    )?))
});

pub use super::models::objects::StaticLoadObjectPatterns;
impl_resolver_singleton!(all, StaticLoadObjectPatterns, |ctx| async {
    let patterns = [
        "c6 44 24 30 01 48 8b d5 4c 89 54 24 28 48 8b c8 89 5c 24 20 e8 | ?? ?? ?? ?? 48 8b 5c 24 50 48 8b 6c 24 58 48 8b 74 24 60 48 83 c4 40 5f c3",
        "4c 89 6c 24 38 4c 8b c7 c6 44 24 30 01 49 8b d7 48 89 5c 24 28 48 8b c8 44 89 64 24 20 e8 | ?? ?? ?? ?? 48 85 c0",
    ];

    BinaryMatcher::patterns(patterns)?
        .rip4()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});

pub use super::models::objects::StaticLoadObjectString;
impl_resolver_singleton!(all, StaticLoadObjectString, |ctx| async {
    BinaryMatcher::patterns(
        [
            "Failed to find object '{ClassName} {OuterName}.{ObjectName}'\0",
            "Failed to find object '{ObjectPath}'\0",
        ]
        .map(util::utf16_pattern),
    )?
    .references()
    .root_functions()
    .addresses()
    .ensure_one()
    .resolve(ctx)
    .await
    .map(|node| Self(*node.value))
});
