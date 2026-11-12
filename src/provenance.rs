use std::sync::Arc;

use crate::{FunctionEntry, HasAddress, InstructionSite};

/// An immutable candidate and its statically typed predecessors.
/// Values and parents are shared; cloning a node never clones its value.
/// Source nodes have one unit parent. Ordinary steps have one parent; sets and
/// uniqueness checks retain all contributors in encounter order.
/// Equality includes ancestry. Matcher sets compare only current values.
/// Values and parents must be Send + Sync for shared asynchronous evaluation.
///
/// ```
/// use binary_bloodhound::{Function, FunctionEntry, Matcher, Reference};
/// let source = Matcher::from_value(|()| Ok(FunctionEntry {
///     start: 0x1000, end: 0x1100, unwind: None,
/// }));
/// let matcher = source.references().root_functions()
///     .map(|root: &Function<Reference<Function<()>>>| {
///         (root.value.start, root.parent().value.0, root.parent().parent().value.start)
///     });
/// ```
///
/// Parents are checked statically, not recovered through downcasts:
/// ```compile_fail
/// use binary_bloodhound::BinaryMatcher;
/// let invalid = BinaryMatcher::address(0x1000).root_functions()
///     .map(|root| root.parent().value.start); // Parent value is u64.
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct Trace<T, P = ()> {
    pub value: Arc<T>,
    parents: Vec<Arc<P>>,
}

pub type Function<P = ()> = Trace<FunctionEntry, P>;
pub type Reference<P = ()> = Trace<InstructionSite, P>;

impl<T, P> std::ops::Deref for Trace<T, P> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T, P> Clone for Trace<T, P> {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            parents: self.parents.clone(),
        }
    }
}

impl<T> Trace<T> {
    pub(crate) fn root(value: T) -> Self {
        Self::child(value, Arc::new(()))
    }
}

impl<T> Trace<T, T> {
    pub(crate) fn joined(value: T) -> Self {
        let value = Arc::new(value);
        Self {
            value: Arc::clone(&value),
            parents: vec![value],
        }
    }
}

impl<T, P> Trace<T, P> {
    pub(crate) fn child(value: T, parent: Arc<P>) -> Self {
        Self {
            value: Arc::new(value),
            parents: vec![parent],
        }
    }

    pub(crate) fn children(
        values: impl IntoIterator<Item = T>,
        parent: P,
    ) -> impl Iterator<Item = Self> {
        let parent = Arc::new(parent);
        values
            .into_iter()
            .map(move |value| Self::child(value, Arc::clone(&parent)))
    }

    /// First contributing parent; parents() includes every merged derivation.
    /// This never returns an arbitrary last contributor or discards other paths.
    pub fn parent(&self) -> &P {
        &self.parents[0]
    }

    pub fn parents(&self) -> &[Arc<P>] {
        &self.parents
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.parents.extend(other.parents);
    }

    pub(crate) fn map_parents<Q>(self, func: impl Fn(Arc<P>) -> Q) -> Trace<T, Q> {
        Trace {
            value: self.value,
            parents: self
                .parents
                .into_iter()
                .map(|parent| Arc::new(func(parent)))
                .collect(),
        }
    }

    pub(crate) fn compose<A>(self, outer: Arc<A>) -> Trace<T, Composition<A, P>> {
        self.map_parents(|inner| Composition {
            outer: Arc::clone(&outer),
            inner,
        })
    }
}

/// Both sides of a composed derivation, without discarding inner ancestry.
#[derive(Debug, PartialEq, Eq)]
pub struct Composition<A, B> {
    pub outer: Arc<A>,
    pub inner: Arc<B>,
}

/// A contributor from either branch of a heterogeneous set operation.
#[derive(Debug, PartialEq, Eq)]
pub enum Contributor<A, B> {
    Left(Arc<A>),
    Right(Arc<B>),
}

impl<T: HasAddress, P> HasAddress for Trace<T, P> {
    fn address(&self) -> u64 {
        self.value.address()
    }
}
