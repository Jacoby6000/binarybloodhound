//! Immutable matcher pipelines with automatic, statically typed provenance.
//!
//! Sources produce [`Trace`] nodes with unit parents. Transformations borrow nodes
//! and retain them as parents of replacement values. Filters and selections retain
//! the original nodes. Set operations merge all contributors to equal values.
//!
//! ```
//! use binary_bloodhound::BinaryMatcher;
//! let matcher = BinaryMatcher::address(0x1000).references().root_functions()
//!     .map(|root| (root.value.start, root.parent().value.0));
//! ```
//!
//! Resolution returns nodes, not bare values. Read a node's shared value at the
//! application boundary; ancestry remains available through parent()/parents().
//!
//! ```no_run
//! use binary_bloodhound::BinaryMatcher;
//! use patternsleuth::resolvers::{AsyncContext, Result};
//! async fn resolve_address(ctx: &AsyncContext<'_>) -> Result<u64> {
//!     let node = BinaryMatcher::address(0x1000).ensure_one().resolve(ctx).await?;
//!     Ok(*node.value)
//! }
//! ```

mod cardinality;
mod composition;
mod context;
mod disassembly;
mod evaluation;
mod functions;
mod navigation;
mod nodes;
mod pipeline;
mod provenance;
mod sets;
mod sources;

pub use cardinality::{Cardinality, ExactlyOne, Variable};
pub use composition::{ForkMatcher, ForkOutput, SequenceParents};
pub use context::WithContext;
pub use disassembly::Control;
pub use evaluation::MatchContext;
pub use navigation::stages;
pub use nodes::{Address, Call, FunctionEntry, HasAddress, InstructionSite};
pub use pipeline::{Matcher, Resolved};
pub use provenance::{Composition, Contributor, Function, Reference, Trace};
pub use sources::IntoPattern;

/// Address-producing source. All candidates carry typed ancestry automatically.
pub type BinaryMatcher<'scope> = Matcher<'scope, (), u64>;

#[cfg(test)]
mod tests;
