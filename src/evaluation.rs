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
            .flat_map(|address| reference_patterns(address, calls));
        join_all(patterns.map(|pattern| self.scan(pattern)))
            .await
            .into_iter()
            .flatten()
            .collect()
    }
}

fn reference_patterns(address: u64, calls: bool) -> impl Iterator<Item = Pattern> {
    let signatures = if calls {
        vec![format!("e8 X0x{address:X}"), format!("e9 X0x{address:X}")]
    } else {
        // REX.W and REX.W|R, each with the eight RIP-relative LEA destinations.
        let mut signatures: Vec<_> = [0x48, 0x4c]
            .into_iter()
            .flat_map(|rex| {
                (0..8).map(move |register| {
                    let modrm = 0x05 + register * 8;
                    format!("{rex:02X} 8D {modrm:02X} X0x{address:X}")
                })
            })
            .collect();
        if u32::try_from(address).is_ok() {
            signatures.extend((0xb8..=0xbf).map(|opcode| format!("{opcode:02X} 0x{address:X}")));
        }
        signatures
    };
    signatures
        .into_iter()
        .map(|signature| Pattern::new(signature).expect("generated reference pattern"))
}

#[cfg(test)]
mod tests {
    use super::reference_patterns;

    #[test]
    fn data_reference_patterns_cover_lea_registers_in_native_order() {
        let address = 0x1_4000_4000_u64;
        let patterns: Vec<_> = reference_patterns(address, false).collect();

        assert_eq!(patterns.len(), 16);
        for (index, pattern) in patterns.iter().enumerate() {
            let mut instruction = vec![
                if index < 8 { 0x48 } else { 0x4c },
                0x8d,
                0x05 + (index % 8) as u8 * 8,
            ];
            instruction.extend(0_i32.to_le_bytes());

            assert!(pattern.is_match(&instruction, (address - 7) as usize, 0));
        }
    }

    #[test]
    fn data_reference_patterns_include_immediates_only_for_u32_addresses() {
        let address = u32::MAX;
        let patterns: Vec<_> = reference_patterns(u64::from(address), false).collect();

        assert_eq!(patterns.len(), 24);
        for (index, pattern) in patterns[16..].iter().enumerate() {
            let mut instruction = vec![0xb8 + index as u8];
            instruction.extend(address.to_le_bytes());

            assert!(pattern.is_match(&instruction, 0, 0));
        }
        assert_eq!(
            reference_patterns(u64::from(address) + 1, false).count(),
            16
        );
    }

    #[test]
    fn call_reference_patterns_cover_direct_calls_then_jumps() {
        let address = 0x1_4000_4000;
        let patterns: Vec<_> = reference_patterns(address, true).collect();

        assert_eq!(patterns.len(), 2);
        for (pattern, opcode) in patterns.iter().zip([0xe8, 0xe9]) {
            let mut instruction = vec![opcode];
            instruction.extend(0_i32.to_le_bytes());

            assert!(pattern.is_match(&instruction, (address - 5) as usize, 0));
        }
    }
}
