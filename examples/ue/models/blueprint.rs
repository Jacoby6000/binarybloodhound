//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/blueprint_library.rs>

use patternsleuth::resolvers::ResolveError;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct BlueprintLibraryInit {
    pub uclass_compiled_in_defer: u64,
    pub uobject_compiled_in_defer: u64,
    pub construct_uclass: u64,
    pub get_private_static_class_body: u64,
    pub uobject_static_class: u64,
    pub ublueprint_function_library_static_class: u64,
}

impl FromStr for BlueprintLibraryInit {
    type Err = ResolveError;
    fn from_str(_s: &str) -> std::result::Result<Self, Self::Err> {
        Err(ResolveError::new_msg("unimplemented"))
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct UFunctionBind(pub u64);
