/// A known address, not necessarily a function entry or instruction site.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

/// An instruction's address.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InstructionSite(pub u64);

/// Root-function metadata. The end address is exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionEntry {
    pub start: u64,
    pub end: u64,
    pub unwind: Option<u64>,
}

impl FunctionEntry {
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    pub(crate) fn checked_range(&self) -> patternsleuth::resolvers::Result<std::ops::Range<u64>> {
        if self.end < self.start {
            return Err(patternsleuth::resolvers::ResolveError::new_msg(format!(
                "invalid function range: {:#x}..{:#x}",
                self.start, self.end
            )));
        }
        Ok(self.start..self.end)
    }
}

/// A direct near-call instruction and its destination. Targets are not normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Call {
    pub site: InstructionSite,
    pub target: Address,
}

pub trait HasAddress {
    fn address(&self) -> u64;
}

impl HasAddress for u64 {
    fn address(&self) -> u64 {
        *self
    }
}

impl HasAddress for Address {
    fn address(&self) -> u64 {
        self.0
    }
}

impl HasAddress for InstructionSite {
    fn address(&self) -> u64 {
        self.0
    }
}

impl HasAddress for FunctionEntry {
    fn address(&self) -> u64 {
        self.start
    }
}

#[cfg(test)]
mod tests {
    use super::FunctionEntry;

    #[test]
    fn checked_function_ranges_allow_empty_ranges() {
        for (start, end) in [(0x1000, 0x1000), (0x1000, 0x1010)] {
            let function = FunctionEntry {
                start,
                end,
                unwind: None,
            };

            assert_eq!(function.checked_range().unwrap(), start..end);
        }
    }

    #[test]
    fn checked_function_ranges_reject_reversed_bounds() {
        let function = FunctionEntry {
            start: 0x1010,
            end: 0x1000,
            unwind: None,
        };

        assert_eq!(
            function.checked_range().unwrap_err().to_string(),
            "invalid function range: 0x1010..0x1000"
        );
    }
}
