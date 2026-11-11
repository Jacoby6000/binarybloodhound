//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/engine_version.rs>

use patternsleuth::resolvers::ResolveError;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct BuildChangeList(pub String);

impl FromStr for BuildChangeList {
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
pub struct InternalProjectName {
    pub internal_project_name: u64,
    pub compiled_in_project_name: Option<String>,
}

impl FromStr for InternalProjectName {
    type Err = ResolveError;
    fn from_str(_s: &str) -> std::result::Result<Self, Self::Err> {
        Err(ResolveError::new_msg("unimplemented"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum BuildConfiguration {
    /// Also Debug and DebugGame.
    Development,
    Test,
    Shipping,
}

impl FromStr for BuildConfiguration {
    type Err = ResolveError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Development" => Ok(Self::Development),
            "Test" => Ok(Self::Test),
            "Shipping" => Ok(Self::Shipping),
            _ => Err(ResolveError::new_msg(
                "expected Development, Test or Shipping",
            )),
        }
    }
}

/// The STATS macro, independent of the build configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum Stats {
    Off,
    On,
}

impl FromStr for Stats {
    type Err = ResolveError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "Off" => Ok(Self::Off),
            "On" => Ok(Self::On),
            _ => Err(ResolveError::new_msg("expected On or Off")),
        }
    }
}
