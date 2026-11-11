//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/engine_version.rs>

use patternsleuth::resolvers::ResolveError;
use std::{collections::BTreeSet, str::FromStr};

#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct CustomVersionRegistry(pub(in crate::ue) u64);

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::ue) struct Guid(pub(in crate::ue) [u8; 16]);

impl std::fmt::Debug for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{")?;
        for (i, byte) in self.0.iter().enumerate() {
            if i == 4 || i == 6 || i == 8 || i == 10 {
                f.write_str("-")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        write!(f, "}}")
    }
}

#[cfg(feature = "serde-resolvers")]
impl serde::Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hex_string = self
            .0
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<String>();
        serializer.serialize_str(&hex_string)
    }
}

#[cfg(feature = "serde-resolvers")]
impl<'de> serde::Deserialize<'de> for Guid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct GuidVisitor;

        impl<'de> serde::de::Visitor<'de> for GuidVisitor {
            type Value = Guid;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a hex string of 32 characters")
            }

            fn visit_str<E>(self, value: &str) -> Result<Guid, E>
            where
                E: serde::de::Error,
            {
                let clean = value.replace("-", "");
                if clean.len() != 32 {
                    return Err(E::custom(format!(
                        "expected 32 hex characters, got {}",
                        clean.len()
                    )));
                }

                let mut bytes = [0u8; 16];
                for i in 0..16 {
                    let byte_str = &clean[i * 2..i * 2 + 2];
                    bytes[i] =
                        u8::from_str_radix(byte_str, 16).map_err(|_| E::custom("invalid GUID"))?;
                }
                Ok(Guid(bytes))
            }
        }

        deserializer.deserialize_str(GuidVisitor)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub(in crate::ue) struct CustomVersion {
    pub(in crate::ue) guid: Guid,
    pub(in crate::ue) version: u32,
    pub(in crate::ue) name: String,
}

impl std::fmt::Debug for CustomVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CustomVersion({:?}, {:>3}, {})",
            self.guid, self.version, self.name
        )
    }
}

#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct StaticCustomVersions(pub(in crate::ue) BTreeSet<CustomVersion>);

impl FromStr for StaticCustomVersions {
    type Err = ResolveError;
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Err(ResolveError::new_msg("unimplemented"))
    }
}
