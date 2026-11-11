use std::{marker::PhantomData, sync::Arc};

use futures::future::BoxFuture;
use patternsleuth::resolvers::{AsyncContext, ResolveError, Result};

use super::{Cardinality, ExactlyOne, FunctionEntry, MatchContext, Variable, WithContext};

pub(super) trait Run<I, O>: Send + Sync {
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<O>>>
    where
        I: 'ctx,
        O: 'ctx;
}

struct AsyncStage<F>(F);

struct SyncStage<F>(F);

impl<I: Send, O, F> Run<I, O> for SyncStage<F>
where
    F: Fn(I) -> Result<Vec<O>> + Send + Sync,
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        _: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<O>>>
    where
        I: 'ctx,
        O: 'ctx,
    {
        Box::pin(async move { (self.0)(input) })
    }
}

impl<I, O, F> Run<I, O> for AsyncStage<F>
where
    F: for<'ctx, 'image> Fn(I, MatchContext<'ctx, 'image>) -> BoxFuture<'ctx, Result<Vec<O>>>
        + Send
        + Sync,
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<O>>>
    where
        I: 'ctx,
        O: 'ctx,
    {
        (self.0)(input, ctx)
    }
}

struct Identity<C>(PhantomData<C>);

impl<T: Send, C: Cardinality> Run<C::Output<T>, T> for Identity<C> {
    fn run<'ctx, 'image>(
        &'ctx self,
        input: C::Output<T>,
        _: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<T>>>
    where
        C::Output<T>: 'ctx,
        T: 'ctx,
    {
        Box::pin(async move { Ok(C::into_items(input)) })
    }
}

struct Then<'scope, I, O: Send, T, C: Cardinality, D: Cardinality> {
    first: Matcher<'scope, I, O, C>,
    next: Matcher<'scope, C::Output<O>, T, D>,
}

impl<'scope, I: Send + 'scope, O: Send + 'scope, T: Send + 'scope, C: Cardinality, D: Cardinality>
    Run<I, T> for Then<'scope, I, O, T, C, D>
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<T>>>
    where
        I: 'ctx,
        T: 'ctx,
    {
        Box::pin(async move {
            let input = C::finish(self.first.run_in(input, ctx).await?)?;
            self.next.run_in(input, ctx).await
        })
    }
}

struct Fork<'scope, I, O, T, C: Cardinality, D: Cardinality> {
    left: Matcher<'scope, I, O, C>,
    right: Matcher<'scope, I, T, D>,
}

/// Resolved values from two fork branches, retaining each branch's output shape.
pub type ForkOutput<O, T, C, D> = (<C as Cardinality>::Output<O>, <D as Cardinality>::Output<T>);

impl<
    'scope,
    I: Clone + Send + 'scope,
    O: Send + 'scope,
    T: Send + 'scope,
    C: Cardinality,
    D: Cardinality,
> Run<I, (C::Output<O>, D::Output<T>)> for Fork<'scope, I, O, T, C, D>
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<(C::Output<O>, D::Output<T>)>>>
    where
        I: 'ctx,
        (C::Output<O>, D::Output<T>): 'ctx,
    {
        Box::pin(async move {
            let left = C::finish(self.left.run_in(input.clone(), ctx).await?)?;
            let right = D::finish(self.right.run_in(input, ctx).await?)?;
            Ok(vec![(left, right)])
        })
    }
}

enum SetOperation {
    Union,
    Intersect,
}

struct SetAll<'scope, I, T> {
    matchers: Vec<Matcher<'scope, I, T>>,
    operation: SetOperation,
}

impl<'scope, I: Clone + Send + 'scope, T: PartialEq + Send + 'scope> Run<I, T>
    for SetAll<'scope, I, T>
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<T>>>
    where
        I: 'ctx,
        T: 'ctx,
    {
        Box::pin(async move {
            let mut result = Vec::new();
            for (index, matcher) in self.matchers.iter().enumerate() {
                let items = matcher.run_in(input.clone(), ctx).await?;
                if matches!(self.operation, SetOperation::Intersect) && index > 0 {
                    result.retain(|item| items.contains(item));
                } else {
                    for item in items {
                        if !result.contains(&item) {
                            result.push(item);
                        }
                    }
                }
            }
            Ok(result)
        })
    }
}

pub(super) struct Sub<'scope, I, T, C: Cardinality, D: Cardinality> {
    pub functions: Matcher<'scope, I, FunctionEntry, C>,
    pub matcher: Matcher<'scope, (), T, D>,
}

impl<'scope, I: Send + 'scope, T: Send + 'scope, C: Cardinality, D: Cardinality> Run<I, T>
    for Sub<'scope, I, T, C, D>
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<T>>>
    where
        I: 'ctx,
        T: 'ctx,
    {
        Box::pin(async move {
            let functions = self.functions.run_in(input, ctx).await?;
            let mut result = Vec::new();
            for function in functions {
                if function.end < function.start {
                    return Err(ResolveError::new_msg(format!(
                        "invalid function range: {:#x}..{:#x}",
                        function.start, function.end
                    )));
                }
                let inner = ctx.within(function.start..function.end);
                if inner.bounds().is_some_and(|range| range.start < range.end) {
                    result.extend(self.matcher.run_in((), inner).await?);
                }
            }
            Ok(result)
        })
    }
}

/// A reusable pipeline from input I to candidates O. C controls resolution shape:
/// Variable resolves to Vec<O>; ExactlyOne resolves to O.
/// Clones share stages, not results. Callbacks may borrow for 'scope.
///
/// ```
/// use binary_bloodhound::BinaryMatcher;
/// let matcher = BinaryMatcher::address(0x1000)
///     .ensure_one().offset(4).map(|address| format!("{address:#x}"));
/// ```
///
/// O is always one candidate's type, even when that candidate is a collection.
/// Use items for a collection input, or new for one input value:
///
/// ```
/// use binary_bloodhound::{ExactlyOne, Matcher};
/// let items: Matcher<Vec<u64>, u64> = Matcher::items();
/// let scalar: Matcher<u64, u64, ExactlyOne> = Matcher::new::<u64>();
/// let count = Matcher::items::<u64>().transform(|addresses| addresses.len());
/// ```
///
/// Borrowed inputs, outputs and callback captures may live for 'scope:
///
/// ```
/// use binary_bloodhound::{ExactlyOne, Matcher};
/// fn strip_prefix<'a>(prefix: &'a str) -> Matcher<'a, &'a str, &'a str, ExactlyOne> {
///     Matcher::new::<&str>().map(move |value| value.strip_prefix(prefix).unwrap_or(value))
/// }
/// ```
///
/// A stage cannot outlive captured data:
///
/// ```compile_fail
/// use binary_bloodhound::Matcher;
/// let stage;
/// {
///     let prefix = String::from("prefix:");
///     stage = Matcher::new::<&str>().map(|value| value.strip_prefix(prefix.as_str()).unwrap());
/// }
/// drop(stage);
/// ```
///
/// Composition checks resolved output and next-stage input types:
///
/// ```
/// use binary_bloodhound::Matcher;
/// let stage = Matcher::new::<u64>().map(|address| address.to_string())
///     .then(Matcher::new::<String>());
/// ```
///
/// ```compile_fail
/// use binary_bloodhound::Matcher;
/// let stage = Matcher::new::<u64>().map(|address| address.to_string());
/// let invalid = stage.then(Matcher::items::<u64>());
/// ```
///
/// Ordinary callbacks receive data only; context access requires with_context:
///
/// ```
/// use binary_bloodhound::BinaryMatcher;
/// use patternsleuth::MemoryTrait;
/// let stage = BinaryMatcher::address(0x1000).map(|address| address + 1)
///     .with_context().try_map(|(ctx, address)| Ok(ctx.image().memory.u8(address)?));
/// ```
///
/// ```compile_fail
/// use binary_bloodhound::BinaryMatcher;
/// let invalid = BinaryMatcher::address(0x1000).map(|address, ctx| address);
/// ```
#[must_use = "matchers do nothing until run or resolved"]
pub struct Matcher<'scope, I, O, C: Cardinality = Variable> {
    run: Arc<dyn Run<I, O> + 'scope>,
    cardinality: PhantomData<C>,
}

impl<'scope, I, O, C: Cardinality> Clone for Matcher<'scope, I, O, C> {
    fn clone(&self) -> Self {
        Self {
            run: self.run.clone(),
            cardinality: PhantomData,
        }
    }
}

impl<I, O, C: Cardinality> std::fmt::Display for Matcher<'_, I, O, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Matcher")
    }
}

impl<'scope, I: Send + 'scope, O: Send + 'scope> Matcher<'scope, I, O> {
    /// Build an asynchronous source of zero or more candidates.
    /// Use ctx.scan to honor function scopes; ctx.native explicitly bypasses them.
    pub fn from_async<F>(run: F) -> Self
    where
        F: for<'ctx, 'image> Fn(I, MatchContext<'ctx, 'image>) -> BoxFuture<'ctx, Result<Vec<O>>>
            + Send
            + Sync
            + 'scope,
    {
        Self::from_run(AsyncStage(run))
    }

    /// Build a synchronous source of zero or more candidates.
    pub fn from_sync<F>(run: F) -> Self
    where
        F: Fn(I) -> Result<Vec<O>> + Send + Sync + 'scope,
    {
        Self::from_run(SyncStage(run))
    }
}

impl<'scope, I: Send + 'scope, O: Send + 'scope, C: Cardinality> Matcher<'scope, I, O, C> {
    pub(super) fn from_run(run: impl Run<I, O> + 'scope) -> Self {
        Self {
            run: Arc::new(run),
            cardinality: PhantomData,
        }
    }

    pub async fn run(&self, input: I, ctx: &AsyncContext<'_>) -> Result<C::Output<O>> {
        C::finish(self.run_in(input, MatchContext::new(ctx)).await?)
    }

    pub(crate) async fn run_in(&self, input: I, ctx: MatchContext<'_, '_>) -> Result<Vec<O>> {
        self.run.run(input, ctx).await
    }

    /// Drop the exactly-one guarantee without changing the candidates.
    pub fn into_variable(self) -> Matcher<'scope, I, O> {
        Matcher {
            run: self.run,
            cardinality: PhantomData,
        }
    }

    pub fn with_context(self) -> WithContext<'scope, I, O, C> {
        WithContext { matcher: self }
    }

    /// Pass the resolved upstream output into the next stage; retain its cardinality.
    pub fn then<T: Send + 'scope, D: Cardinality>(
        self,
        next: Matcher<'scope, C::Output<O>, T, D>,
    ) -> Matcher<'scope, I, T, D> {
        Matcher::from_run(Then { first: self, next })
    }

    /// Transform one candidate at a time, retaining order, duplicates and cardinality.
    pub fn map<T, F>(self, func: F) -> Matcher<'scope, I, T, C>
    where
        T: Send + 'scope,
        F: Fn(O) -> T + Send + Sync + 'scope,
    {
        self.try_map(move |item| Ok(func(item)))
    }

    /// Map each candidate to an optional value, discarding None results.
    /// Preserve order and duplicates; filtering returns Variable cardinality.
    pub fn map_filter<T, F>(self, func: F) -> Matcher<'scope, I, T>
    where
        T: Send + 'scope,
        F: Fn(O) -> Option<T> + Send + Sync + 'scope,
    {
        self.try_map_filter(move |item| Ok(func(item)))
    }

    /// Fallible map_filter; stop at the first callback error.
    pub fn try_map_filter<T, F>(self, func: F) -> Matcher<'scope, I, T>
    where
        T: Send + 'scope,
        F: Fn(O) -> Result<Option<T>> + Send + Sync + 'scope,
    {
        self.with_context()
            .try_map_filter(move |(_, item)| func(item))
    }

    /// Fallibly transform candidates, stopping at the first error.
    pub fn try_map<T, F>(self, func: F) -> Matcher<'scope, I, T, C>
    where
        T: Send + 'scope,
        F: Fn(O) -> Result<T> + Send + Sync + 'scope,
    {
        self.with_context().try_map(move |(_, item)| func(item))
    }

    /// Transform the resolved whole output into one candidate.
    pub fn transform<T, F>(self, func: F) -> Matcher<'scope, I, T, ExactlyOne>
    where
        T: Send + 'scope,
        F: Fn(C::Output<O>) -> T + Send + Sync + 'scope,
    {
        self.try_transform(move |output| Ok(func(output)))
    }

    pub fn try_transform<T, F>(self, func: F) -> Matcher<'scope, I, T, ExactlyOne>
    where
        T: Send + 'scope,
        F: Fn(C::Output<O>) -> Result<T> + Send + Sync + 'scope,
    {
        self.with_context()
            .try_transform(move |(_, output)| func(output))
    }

    /// Transform the complete candidate collection into a new variable collection.
    pub fn transform_all<T, F>(self, func: F) -> Matcher<'scope, I, T>
    where
        T: Send + 'scope,
        F: Fn(Vec<O>) -> Vec<T> + Send + Sync + 'scope,
    {
        self.try_transform_all(move |items| Ok(func(items)))
    }

    pub fn try_transform_all<T, F>(self, func: F) -> Matcher<'scope, I, T>
    where
        T: Send + 'scope,
        F: Fn(Vec<O>) -> Result<Vec<T>> + Send + Sync + 'scope,
    {
        self.with_context()
            .try_transform_all(move |(_, items)| func(items))
    }

    /// Build and evaluate another matcher for each candidate.
    /// Inner matchers share the current image and search bounds, run sequentially,
    /// and retain their result order and duplicates. Empty input skips the callback.
    ///
    /// ```
    /// use binary_bloodhound::BinaryMatcher;
    /// let matcher = BinaryMatcher::address(0x1000).flat_map(|address| {
    ///     BinaryMatcher::address(address).root_functions()
    ///         .map(move |function| (address, function))
    /// });
    /// ```
    ///
    /// Ordinary vectors use expand, not flat_map:
    /// ```compile_fail
    /// use binary_bloodhound::BinaryMatcher;
    /// let invalid = BinaryMatcher::address(0x1000).flat_map(|address| vec![address]);
    /// ```
    pub fn flat_map<T, D, F>(self, func: F) -> Matcher<'scope, I, T>
    where
        T: Send + 'scope,
        D: Cardinality,
        F: Fn(O) -> Matcher<'scope, (), T, D> + Send + Sync + 'scope,
    {
        self.try_flat_map(move |item| Ok(func(item)))
    }

    /// Fallible matcher construction; callback and inner errors skip later candidates.
    pub fn try_flat_map<T, D, F>(self, func: F) -> Matcher<'scope, I, T>
    where
        T: Send + 'scope,
        D: Cardinality,
        F: Fn(O) -> Result<Matcher<'scope, (), T, D>> + Send + Sync + 'scope,
    {
        self.with_context()
            .try_flat_map(move |(_, item)| func(item))
    }

    /// Expand one candidate into a vector without evaluating another matcher.
    pub fn expand<T, F>(self, func: F) -> Matcher<'scope, I, T>
    where
        T: Send + 'scope,
        F: Fn(O) -> Vec<T> + Send + Sync + 'scope,
    {
        self.try_expand(move |item| Ok(func(item)))
    }

    pub fn try_expand<T, F>(self, func: F) -> Matcher<'scope, I, T>
    where
        T: Send + 'scope,
        F: Fn(O) -> Result<Vec<T>> + Send + Sync + 'scope,
    {
        self.with_context().try_expand(move |(_, item)| func(item))
    }

    pub fn filter_each<F>(self, predicate: F) -> Matcher<'scope, I, O>
    where
        F: Fn(&O) -> bool + Send + Sync + 'scope,
    {
        self.try_filter(move |item| Ok(predicate(item)))
    }

    pub fn try_filter<F>(self, predicate: F) -> Matcher<'scope, I, O>
    where
        F: Fn(&O) -> Result<bool> + Send + Sync + 'scope,
    {
        self.filter_modify(move |item| Ok(predicate(&item)?.then_some(item)))
    }

    pub fn filter_modify<T, F>(self, func: F) -> Matcher<'scope, I, T>
    where
        T: Send + 'scope,
        F: Fn(O) -> Result<Option<T>> + Send + Sync + 'scope,
    {
        self.with_context()
            .filter_modify(move |(_, item)| func(item))
    }

    /// Require one unique candidate, accepting repeated equal values.
    /// Errors on empty or conflicting results using native resolver errors.
    /// Subsequent maps and address operations retain ExactlyOne.
    pub fn ensure_one(self) -> Matcher<'scope, I, O, ExactlyOne>
    where
        O: std::fmt::Debug + PartialEq,
    {
        self.into_variable()
            .try_transform(patternsleuth::resolvers::ensure_one)
    }

    /// Select by signed index: 0 is first, -1 last. Errors on empty or out-of-range input.
    /// Evaluates the entire upstream stage before selecting; does not require Clone.
    ///
    /// ```
    /// use binary_bloodhound::{ExactlyOne, Matcher};
    /// let second: Matcher<Vec<u64>, u64, ExactlyOne> = Matcher::items().at_index(1);
    /// let penultimate: Matcher<Vec<u64>, u64, ExactlyOne> = Matcher::items().at_index(-2);
    /// ```
    pub fn at_index(self, index: isize) -> Matcher<'scope, I, O, ExactlyOne> {
        self.into_variable().try_transform(move |items| {
            let len = items.len();
            let position = if index < 0 {
                len.checked_sub(index.unsigned_abs())
            } else {
                usize::try_from(index).ok()
            };
            position
                .filter(|&position| position < len)
                .and_then(|position| items.into_iter().nth(position))
                .ok_or_else(|| {
                    ResolveError::new_msg(format!(
                        "candidate index {index} out of range for {len} candidates"
                    ))
                })
        })
    }

    /// Select the first candidate, or error on empty input. Equivalent to at_index(0).
    pub fn first(self) -> Matcher<'scope, I, O, ExactlyOne> {
        self.at_index(0)
    }
    /// Select the last candidate, or error on empty input. Equivalent to at_index(-1).
    pub fn last(self) -> Matcher<'scope, I, O, ExactlyOne> {
        self.at_index(-1)
    }

    /// Evaluate branches sequentially against the same input. Errors skip later branches.
    pub fn fork<T: Send + 'scope, D: Cardinality>(
        self,
        right: Matcher<'scope, I, T, D>,
    ) -> Matcher<'scope, I, ForkOutput<O, T, C, D>, ExactlyOne>
    where
        I: Clone,
    {
        Matcher::from_run(Fork { left: self, right })
    }

    pub fn union<D: Cardinality>(self, other: Matcher<'scope, I, O, D>) -> Matcher<'scope, I, O>
    where
        I: Clone,
        O: PartialEq,
    {
        Matcher::union_all([self.into_variable(), other.into_variable()])
    }

    pub fn intersect<D: Cardinality>(self, other: Matcher<'scope, I, O, D>) -> Matcher<'scope, I, O>
    where
        I: Clone,
        O: PartialEq,
    {
        Matcher::intersect_all([self.into_variable(), other.into_variable()])
    }

    /// Stable union, sequential branches, first-error propagation.
    pub fn union_all(matchers: impl IntoIterator<Item = Self>) -> Matcher<'scope, I, O>
    where
        I: Clone,
        O: PartialEq,
    {
        Matcher::from_run(SetAll {
            matchers: matchers.into_iter().map(Self::into_variable).collect(),
            operation: SetOperation::Union,
        })
    }

    /// Stable intersection, sequential branches, first-error propagation.
    pub fn intersect_all(matchers: impl IntoIterator<Item = Self>) -> Matcher<'scope, I, O>
    where
        I: Clone,
        O: PartialEq,
    {
        Matcher::from_run(SetAll {
            matchers: matchers.into_iter().map(Self::into_variable).collect(),
            operation: SetOperation::Intersect,
        })
    }
}

impl<'scope> Matcher<'scope, (), ()> {
    /// Begin with one input value as one candidate, even if it is a collection.
    pub fn new<T: Send + 'scope>() -> Matcher<'scope, T, T, ExactlyOne> {
        Matcher::identity()
    }

    /// Begin with a vector input as a variable collection of candidates.
    pub fn items<T: Send + 'scope>() -> Matcher<'scope, Vec<T>, T> {
        Matcher::identity()
    }

    /// Build a synchronous source of exactly one candidate.
    pub fn from_value<I: Send + 'scope, O: Send + 'scope, F>(
        run: F,
    ) -> Matcher<'scope, I, O, ExactlyOne>
    where
        F: Fn(I) -> Result<O> + Send + Sync + 'scope,
    {
        Self::new::<I>().try_map(run)
    }
}

impl<'scope, T: Send + 'scope, C: Cardinality> Matcher<'scope, C::Output<T>, T, C> {
    pub fn identity() -> Self {
        Self::from_run(Identity::<C>(PhantomData))
    }
}

impl<'scope, O: Send + 'scope, C: Cardinality> Matcher<'scope, (), O, C> {
    pub async fn resolve(&self, ctx: &AsyncContext<'_>) -> Result<C::Output<O>> {
        self.run((), ctx).await
    }
}

impl<'scope, I: Send + 'scope, O: Copy + Send + 'scope, C: Cardinality> Matcher<'scope, I, O, C> {
    pub fn filter<F>(self, predicate: F) -> Matcher<'scope, I, O>
    where
        F: Fn(O) -> bool + Send + Sync + 'scope,
    {
        self.filter_each(move |item| predicate(*item))
    }
}

impl<'scope, I: Send + 'scope, T: Send + 'scope> Matcher<'scope, I, (Vec<T>, Vec<T>), ExactlyOne> {
    pub fn concat(self) -> Matcher<'scope, I, T> {
        self.expand(|(mut left, right)| {
            left.extend(right);
            left
        })
    }
}
