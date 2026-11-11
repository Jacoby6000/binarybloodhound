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
