//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/aes.rs>

use patternsleuth::resolvers::ResolveError;
use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

#[derive(PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct AESKeys(pub(in crate::ue) Vec<AESKey>);

impl Debug for AESKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AESKeys ")?;
        f.debug_list().entries(self.0.iter()).finish()
    }
}

#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct AESKey(pub(in crate::ue) [u8; 32]);

impl Display for AESKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Debug for AESKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl FromStr for AESKeys {
    type Err = ResolveError;
    fn from_str(_s: &str) -> std::result::Result<Self, Self::Err> {
        Err(ResolveError::new_msg("unimplemented"))
    }
}
