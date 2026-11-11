use futures::future::BoxFuture;
use patternsleuth::resolvers::Result;
use std::marker::PhantomData;

use super::{Cardinality, ExactlyOne, MatchContext, Matcher, Variable};

struct Transform<'scope, I, O, C: Cardinality, F> {
    matcher: Matcher<'scope, I, O, C>,
    func: F,
}

struct FlatMap<'scope, I, O, C: Cardinality, D: Cardinality, F> {
    matcher: Matcher<'scope, I, O, C>,
    func: F,
    inner_cardinality: PhantomData<D>,
}

impl<
    'scope,
    I: Send + 'scope,
    O: Send + 'scope,
    U: Send + 'scope,
    C: Cardinality,
    D: Cardinality,
    F,
> super::pipeline::Run<I, U> for FlatMap<'scope, I, O, C, D, F>
where
    F: Fn((MatchContext<'_, '_>, O)) -> Result<Matcher<'scope, (), U, D>> + Send + Sync,
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<U>>>
    where
        I: 'ctx,
        U: 'ctx,
    {
        Box::pin(async move {
            let items = self.matcher.run_in(input, ctx).await?;
            let mut result = Vec::new();
            for item in items {
                let matcher = (self.func)((ctx, item))?;
                result.extend(matcher.run_in((), ctx).await?);
            }
            Ok(result)
        })
    }
}

impl<'scope, I: Send + 'scope, O: Send + 'scope, U: Send, C: Cardinality, F>
    super::pipeline::Run<I, U> for Transform<'scope, I, O, C, F>
where
    F: Fn((MatchContext<'_, '_>, Vec<O>)) -> Result<Vec<U>> + Send + Sync,
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<U>>>
    where
        I: 'ctx,
        U: 'ctx,
    {
        Box::pin(async move { (self.func)((ctx, self.matcher.run_in(input, ctx).await?)) })
    }
}

/// Supply context to one transformation, then return to data-only callbacks.
/// Mapping preserves cardinality; filtering and expansion return Variable.
///
/// ```compile_fail
/// use binary_bloodhound::BinaryMatcher;
/// let invalid = BinaryMatcher::address(0x1000).ensure_one()
///     .with_context().map(|(ctx, _)| ctx.native());
/// ```
///
/// The adapter is consumed; subsequent callbacks are data-only:
///
/// ```compile_fail
/// use binary_bloodhound::BinaryMatcher;
/// let invalid = BinaryMatcher::address(0x1000).ensure_one()
///     .with_context().map(|(_, address)| address)
///     .map(|(ctx, address)| address);
/// ```
#[must_use = "with_context applies only when followed by a transformation"]
pub struct WithContext<'scope, I, O, C: Cardinality = Variable> {
    pub(super) matcher: Matcher<'scope, I, O, C>,
}

impl<'scope, I: Send + 'scope, O: Send + 'scope, C: Cardinality> WithContext<'scope, I, O, C> {
    fn transform_items<U: Send + 'scope, D: Cardinality, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, D>
    where
        F: Fn((MatchContext<'_, '_>, Vec<O>)) -> Result<Vec<U>> + Send + Sync + 'scope,
    {
        Matcher::from_run(Transform {
            matcher: self.matcher,
            func,
        })
    }

    /// Transform one candidate at a time. Empty collections skip the callback.
    pub fn map<U, F>(self, func: F) -> Matcher<'scope, I, U, C>
    where
        U: Send + 'scope,
        F: Fn((MatchContext<'_, '_>, O)) -> U + Send + Sync + 'scope,
    {
        self.try_map(move |input| Ok(func(input)))
    }

    /// Stop at the first error, retaining cardinality on success.
    pub fn try_map<U, F>(self, func: F) -> Matcher<'scope, I, U, C>
    where
        U: Send + 'scope,
        F: Fn((MatchContext<'_, '_>, O)) -> Result<U> + Send + Sync + 'scope,
    {
        self.transform_items(move |(ctx, items)| {
            items.into_iter().map(|item| func((ctx, item))).collect()
        })
    }

    /// Transform the resolved whole output into one candidate.
    pub fn transform<U, F>(self, func: F) -> Matcher<'scope, I, U, ExactlyOne>
    where
        U: Send + 'scope,
        F: Fn((MatchContext<'_, '_>, C::Output<O>)) -> U + Send + Sync + 'scope,
    {
        self.try_transform(move |input| Ok(func(input)))
    }

    pub fn try_transform<U, F>(self, func: F) -> Matcher<'scope, I, U, ExactlyOne>
    where
        U: Send + 'scope,
        F: Fn((MatchContext<'_, '_>, C::Output<O>)) -> Result<U> + Send + Sync + 'scope,
    {
        self.transform_items(move |(ctx, items)| Ok(vec![func((ctx, C::finish(items)?))?]))
    }

    /// Transform all candidates into a new variable collection.
    pub fn transform_all<U, F>(self, func: F) -> Matcher<'scope, I, U>
    where
        U: Send + 'scope,
        F: Fn((MatchContext<'_, '_>, Vec<O>)) -> Vec<U> + Send + Sync + 'scope,
    {
        self.try_transform_all(move |input| Ok(func(input)))
    }

    pub fn try_transform_all<U, F>(self, func: F) -> Matcher<'scope, I, U>
    where
        U: Send + 'scope,
        F: Fn((MatchContext<'_, '_>, Vec<O>)) -> Result<Vec<U>> + Send + Sync + 'scope,
    {
        self.transform_items(func)
    }

    /// Build and evaluate a matcher for each candidate, using this run's context and bounds.
    /// Inner matchers run sequentially; concatenate their results without deduplication.
    pub fn flat_map<U, D, F>(self, func: F) -> Matcher<'scope, I, U>
    where
        U: Send + 'scope,
        D: Cardinality,
        F: Fn((MatchContext<'_, '_>, O)) -> Matcher<'scope, (), U, D> + Send + Sync + 'scope,
    {
        self.try_flat_map(move |input| Ok(func(input)))
    }

    /// Fallible matcher construction; callback and inner errors stop later candidates.
    pub fn try_flat_map<U, D, F>(self, func: F) -> Matcher<'scope, I, U>
    where
        U: Send + 'scope,
        D: Cardinality,
        F: Fn((MatchContext<'_, '_>, O)) -> Result<Matcher<'scope, (), U, D>>
            + Send
            + Sync
            + 'scope,
    {
        Matcher::from_run(FlatMap {
            matcher: self.matcher,
            func,
            inner_cardinality: PhantomData,
        })
    }

    /// Expand each candidate into an ordinary vector, without evaluating another matcher.
    pub fn expand<U, F>(self, func: F) -> Matcher<'scope, I, U>
    where
        U: Send + 'scope,
        F: Fn((MatchContext<'_, '_>, O)) -> Vec<U> + Send + Sync + 'scope,
    {
        self.try_expand(move |input| Ok(func(input)))
    }

    pub fn try_expand<U, F>(self, func: F) -> Matcher<'scope, I, U>
    where
        U: Send + 'scope,
        F: Fn((MatchContext<'_, '_>, O)) -> Result<Vec<U>> + Send + Sync + 'scope,
    {
        self.transform_items(move |(ctx, items)| {
            let mut result = Vec::new();
            for item in items {
                result.extend(func((ctx, item))?);
            }
            Ok(result)
        })
    }

    pub fn filter_each<F>(self, predicate: F) -> Matcher<'scope, I, O>
    where
        F: Fn((MatchContext<'_, '_>, &O)) -> bool + Send + Sync + 'scope,
    {
        self.try_filter(move |input| Ok(predicate(input)))
    }

    pub fn try_filter<F>(self, predicate: F) -> Matcher<'scope, I, O>
    where
        F: Fn((MatchContext<'_, '_>, &O)) -> Result<bool> + Send + Sync + 'scope,
    {
        self.filter_modify(move |(ctx, item)| Ok(predicate((ctx, &item))?.then_some(item)))
    }

    pub fn filter_modify<U, F>(self, func: F) -> Matcher<'scope, I, U>
    where
        U: Send + 'scope,
        F: Fn((MatchContext<'_, '_>, O)) -> Result<Option<U>> + Send + Sync + 'scope,
    {
        self.try_expand(move |input| Ok(func(input)?.into_iter().collect()))
    }
}

impl<'scope, I: Send + 'scope, O: Copy + Send + 'scope, C: Cardinality>
    WithContext<'scope, I, O, C>
{
    pub fn filter<F>(self, predicate: F) -> Matcher<'scope, I, O>
    where
        F: Fn((MatchContext<'_, '_>, O)) -> bool + Send + Sync + 'scope,
    {
        self.filter_each(move |(ctx, item)| predicate((ctx, *item)))
    }
}

impl<'scope, I: Send + 'scope, C: Cardinality> WithContext<'scope, I, u64, C> {
    pub fn modify_with<F>(self, func: F) -> Matcher<'scope, I, u64, C>
    where
        F: Fn((MatchContext<'_, '_>, u64)) -> Result<u64> + Send + Sync + 'scope,
    {
        self.try_map(func)
    }
}
