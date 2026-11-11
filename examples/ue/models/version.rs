//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/engine_version.rs>

use patternsleuth::resolvers::ResolveError;
use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct EngineVersion {
    pub major: u16,
    pub minor: u16,
}

impl Display for EngineVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl Debug for EngineVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EngineVersion({}.{})", self.major, self.minor)
    }
}

impl FromStr for EngineVersion {
    type Err = ResolveError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (major, minor) = s
            .split_once('.')
            .ok_or(ResolveError::new_msg("expected <major>.<minor e.g.: 5.4"))?;
        let major = major
            .parse::<u16>()
            .map_err(|e| ResolveError::new_msg(e.to_string()))?;
        let minor = minor
            .parse::<u16>()
            .map_err(|e| ResolveError::new_msg(e.to_string()))?;
        Ok(Self { major, minor })
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct EngineVersionStrings {
    pub branch_name: String,
    pub build_date: String,
    pub build_version: String,
}

impl FromStr for EngineVersionStrings {
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
pub struct EngineVersionFingerprint(pub EngineVersion);

impl FromStr for EngineVersionFingerprint {
    type Err = ResolveError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}
