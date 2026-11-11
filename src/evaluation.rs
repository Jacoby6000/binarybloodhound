use std::ops::Range;

use futures::future::join_all;
use patternsleuth::{image::Image, resolvers::AsyncContext, scanner::Pattern};

/// Per-run search bounds over the original image. Memory reads remain unrestricted.
/// Custom asynchronous stages should scan through this context to honor sub scopes.
#[derive(Clone, Copy)]
pub struct MatchContext<'ctx, 'image> {
    native: &'ctx AsyncContext<'image>,
    bounds: Option<(u64, u64)>,
}

impl<'ctx, 'image> MatchContext<'ctx, 'image> {
    pub(crate) fn new(native: &'ctx AsyncContext<'image>) -> Self {
        Self {
            native,
            bounds: None,
        }
    }

    /// Full image, including memory and metadata outside the search bounds.
    pub fn image(&self) -> &Image<'_> {
        self.native.image()
    }

    /// Native resolver context. Its scan methods bypass the search bounds.
    pub fn native(&self) -> &'ctx AsyncContext<'image> {
        self.native
    }

    /// Active half-open search range, or None for a whole-image search.
    pub fn bounds(&self) -> Option<Range<u64>> {
        self.bounds.map(|(start, end)| start..end)
    }

    pub(crate) fn within(self, range: Range<u64>) -> Self {
        let (start, end) = match self.bounds {
            Some((start, end)) => (start.max(range.start), end.min(range.end)),
            None => (range.start, range.end),
        };
        Self {
            bounds: Some((start, end)),
            ..self
        }
    }

    /// Scan only bytes inside the active range. Complete patterns must fit;
    /// result markers and RIP-relative targets retain their absolute addresses.
    pub async fn scan(&self, pattern: Pattern) -> Vec<u64> {
        let Some((start, end)) = self.bounds else {
            return self.native.scan(pattern).await;
        };
        if start >= end {
            return Vec::new();
        }
        let mut matches = Vec::new();
        for section in self.image().memory.sections() {
            let section_start = section.address();
            let section_end = section_start.saturating_add(section.data().len() as u64);
            let lower = start.max(section_start);
            let upper = end.min(section_end);
            if lower >= upper {
                continue;
            }
            let data =
                &section.data()[(lower - section_start) as usize..(upper - section_start) as usize];
            let length = pattern.simple.len();
            if length == 0 || length > data.len() {
                continue;
            }
            // The upstream scanner's short-buffer suffix path drops custom_offset.
            // Bounded searches use its predicate directly and retain result markers.
            for index in 0..=data.len() - length {
                if pattern.is_match(data, lower as usize, index) {
                    matches.push(lower + index as u64 + pattern.custom_offset as u64);
                }
            }
        }
        matches
    }

    pub(crate) async fn references(&self, addresses: &[u64], calls: bool) -> Vec<u64> {
        if self.bounds.is_none() {
            return if calls {
                patternsleuth::resolvers::unreal::util::scan_xcalls(self.native, addresses).await
            } else {
                patternsleuth::resolvers::unreal::util::scan_xrefs(self.native, addresses).await
            };
        }
        let indirect = join_all(addresses.iter().map(|address| {
            self.scan(Pattern::from_bytes(address.to_le_bytes().to_vec()).unwrap())
        }))
        .await;
        let patterns = addresses
            .iter()
            .copied()
            .chain(indirect.into_iter().flatten())
            .flat_map(|address| {
                if calls {
                    return vec![format!("e8 X0x{address:X}"), format!("e9 X0x{address:X}")];
                }
                let mut patterns = [
                    "48 8d 05", "48 8d 0d", "48 8d 15", "48 8d 1d", "48 8d 25", "48 8d 2d",
                    "48 8d 35", "48 8d 3d", "4c 8d 05", "4c 8d 0d", "4c 8d 15", "4c 8d 1d",
                    "4c 8d 25", "4c 8d 2d", "4c 8d 35", "4c 8d 3d",
                ]
                .map(|lea| format!("{lea} X0x{address:X}"))
                .to_vec();
                if u32::try_from(address).is_ok() {
                    patterns.extend(
                        ["b8", "b9", "ba", "bb", "bc", "bd", "be", "bf"]
                            .map(|opcode| format!("{opcode} 0x{address:X}")),
                    );
                }
                patterns
            })
            .map(|signature| Pattern::new(signature).unwrap());
        join_all(patterns.map(|pattern| self.scan(pattern)))
            .await
            .into_iter()
            .flatten()
            .collect()
    }
}
