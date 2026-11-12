use std::sync::Arc;

use patternsleuth::{
    MemoryTrait,
    image::Image,
    resolvers::{ResolveError, Result},
    scanner::Pattern,
};

use crate::HasAddress;

/// Owned bytes from one bracketed capture in a matched pattern.
#[derive(Debug, PartialEq, Eq)]
pub struct Capture {
    pub address: u64,
    pub data: Vec<u8>,
}

impl Capture {
    fn bytes<const N: usize>(&self) -> Result<[u8; N]> {
        self.data.as_slice().try_into().map_err(|_| {
            ResolveError::new_msg(format!(
                "capture at {:#x} requires {N} bytes, found {}",
                self.address,
                self.data.len()
            ))
        })
    }

    /// Decode a signed i32 displacement relative to the capture's end.
    pub fn rip4(&self) -> Result<u64> {
        let displacement = i64::from(i32::from_le_bytes(self.bytes()?));
        self.address
            .checked_add(4)
            .and_then(|base| base.checked_add_signed(displacement))
            .ok_or_else(|| {
                ResolveError::new_msg(format!(
                    "capture RIP-relative target overflow at {:#x}",
                    self.address
                ))
            })
    }

    pub fn u32(&self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes()?))
    }

    pub fn u64(&self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }
}

impl HasAddress for Capture {
    fn address(&self) -> u64 {
        self.address
    }
}

/// A source match with its pattern, user tag, and owned bracketed captures.
/// `address` includes the pattern's result marker; `start` is the first matched byte.
/// Patterns and tags are shared across matches; tags need not implement Clone.
#[derive(Debug, PartialEq, Eq)]
pub struct PatternMatch<Tag = ()> {
    pub address: u64,
    pub start: u64,
    pub pattern: Arc<Pattern>,
    pub tag: Arc<Tag>,
    pub captures: Vec<Capture>,
}

impl<Tag> PatternMatch<Tag> {
    pub(crate) fn read(
        image: &Image<'_>,
        address: u64,
        pattern: Arc<Pattern>,
        tag: Arc<Tag>,
    ) -> Result<Self> {
        let start = address
            .checked_sub(pattern.custom_offset as u64)
            .ok_or_else(|| ResolveError::new_msg("pattern result marker underflow"))?;
        let end = start
            .checked_add(pattern.simple.len() as u64)
            .ok_or_else(|| ResolveError::new_msg("pattern match range overflow"))?;
        let bytes = image.memory.range(start..end)?;
        let captures = pattern
            .captures
            .iter()
            .map(|range| {
                let data = bytes.get(range.clone()).ok_or_else(|| {
                    ResolveError::new_msg(format!(
                        "capture range {}..{} outside matched pattern",
                        range.start, range.end
                    ))
                })?;
                Ok(Capture {
                    address: start + range.start as u64,
                    data: data.to_vec(),
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            address,
            start,
            pattern,
            tag,
            captures,
        })
    }
}

impl<Tag> HasAddress for PatternMatch<Tag> {
    fn address(&self) -> u64 {
        self.address
    }
}
