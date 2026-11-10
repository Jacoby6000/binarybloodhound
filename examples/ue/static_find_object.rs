//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/static_find_object.rs>

use super::util;
use binary_bloodhound::BinaryMatcher;
use patternsleuth::resolvers::{ensure_one, impl_resolver_singleton};

/// ```
/// class UObject * __cdecl StaticFindObjectFast(class UClass *, class UObject *, class FName, bool, bool, enum EObjectFlags, enum EInternalObjectFlags)
/// class UObject * __cdecl StaticFindObjectFast(class UClass *, class UObject *, class FName, bool, enum EObjectFlags, enum EInternalObjectFlags)
/// class UObject * __cdecl StaticFindObjectFast(class UClass *, class UObject *, class FName, bool, bool, enum EObjectFlags)
/// ```
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct StaticFindObjectFast(pub u64);
impl_resolver_singleton!(all, StaticFindObjectFast, |ctx| async {
    BinaryMatcher::pattern(util::utf16_pattern("Illegal call to StaticFindObjectFast() while serializing object data or garbage collecting!\0"))
        .references()
        .root_functions()
        .addresses()
        .try_map(ensure_one)
        .map(Self)
        .resolve(ctx)
        .await
});
