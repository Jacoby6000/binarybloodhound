use std::{fmt::Debug, marker::PhantomData, sync::Arc};

use futures::future::BoxFuture;
use patternsleuth::resolvers::{AsyncContext, ResolveError, Result};

use crate::{
    Cardinality, Composition, ExactlyOne, MatchContext, Trace, Variable, WithContext,
    sets::merge_items,
};

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

struct Transform<'scope, I, O, P, C: Cardinality, F> {
    matcher: Matcher<'scope, I, O, C, P>,
    func: F,
}
impl<
    'scope,
    I: Send + 'scope,
    O: Send + Sync + 'scope,
    P: Send + Sync + 'scope,
    U: Send,
    C: Cardinality,
    F,
> Run<I, U> for Transform<'scope, I, O, P, C, F>
where
    F: Fn((MatchContext<'_, '_>, Vec<Trace<O, P>>)) -> Result<Vec<U>> + Send + Sync,
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

struct Then<'scope, I, O: Send + Sync, P: Send + Sync, T, Q, C: Cardinality, D: Cardinality> {
    first: Matcher<'scope, I, O, C, P>,
    next: Matcher<'scope, C::Output<Trace<O, P>>, T, D, Q>,
}
impl<
    'scope,
    I: Send + 'scope,
    O: Send + Sync + 'scope,
    P: Send + Sync + 'scope,
    T: Send + Sync + 'scope,
    Q: Send + Sync + 'scope,
    C: Cardinality,
    D: Cardinality,
> Run<I, Trace<T, Composition<C::Output<Trace<O, P>>, Q>>> for Then<'scope, I, O, P, T, Q, C, D>
where
    C::Output<Trace<O, P>>: Clone + Sync,
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<Trace<T, Composition<C::Output<Trace<O, P>>, Q>>>>>
    where
        I: 'ctx,
        Trace<T, Composition<C::Output<Trace<O, P>>, Q>>: 'ctx,
    {
        Box::pin(async move {
            let parent = Arc::new(self.first.run_resolved_in(input, ctx).await?);
            let children = self.next.run_in((*parent).clone(), ctx).await?;
            Ok(children
                .into_iter()
                .map(|node| node.compose(Arc::clone(&parent)))
                .collect())
        })
    }
}

pub type ForkOutput<O, T, C, D> = (<C as Cardinality>::Output<O>, <D as Cardinality>::Output<T>);

/// Resolved immutable nodes for a cardinality and parent type.
pub type Resolved<O, P, C> = <C as Cardinality>::Output<Trace<O, P>>;
/// Upstream resolved nodes and an inner contributor from then composition.
pub type SequenceParents<O, P, C, Q> = Composition<Resolved<O, P, C>, Q>;
/// A fork's single result, retaining both branches as value and parent.
pub type ForkMatcher<'scope, I, L, R, C, D> =
    Matcher<'scope, I, ForkOutput<L, R, C, D>, ExactlyOne, ForkOutput<L, R, C, D>>;

type ForkTrace<L, R, C, D> = Trace<ForkOutput<L, R, C, D>, ForkOutput<L, R, C, D>>;

struct Fork<'scope, I, O, P, T, Q, C: Cardinality, D: Cardinality> {
    left: Matcher<'scope, I, O, C, P>,
    right: Matcher<'scope, I, T, D, Q>,
}
impl<
    'scope,
    I: Clone + Send + 'scope,
    O: Send + Sync + 'scope,
    P: Send + Sync + 'scope,
    T: Send + Sync + 'scope,
    Q: Send + Sync + 'scope,
    C: Cardinality,
    D: Cardinality,
> Run<I, ForkTrace<Trace<O, P>, Trace<T, Q>, C, D>> for Fork<'scope, I, O, P, T, Q, C, D>
where
    C::Output<Trace<O, P>>: Sync,
    D::Output<Trace<T, Q>>: Sync,
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<ForkTrace<Trace<O, P>, Trace<T, Q>, C, D>>>>
    where
        I: 'ctx,
        ForkTrace<Trace<O, P>, Trace<T, Q>, C, D>: 'ctx,
    {
        Box::pin(async move {
            let left = self.left.run_resolved_in(input.clone(), ctx).await?;
            let right = self.right.run_resolved_in(input, ctx).await?;
            Ok(vec![Trace::joined((left, right))])
        })
    }
}

/// An immutable pipeline. Every candidate carries typed ancestry automatically.
/// O is one candidate's value, P its parent type, and C its resolution shape.
/// Transformation callbacks borrow nodes and return replacement values.
/// Variable resolves to `Vec<Trace<O, P>>`; ExactlyOne resolves to `Trace<O, P>`.
/// Clones share stages, not evaluation results. Values need not implement Clone.
///
/// ```
/// use binary_bloodhound::BinaryMatcher;
/// let matcher = BinaryMatcher::address(0x1000).first()
///     .map(|node| *node.value + 4)
///     .map(|node| (*node.value, *node.parent().value));
/// ```
///
/// Callbacks cannot consume or mutate a candidate's value:
/// ```compile_fail
/// use binary_bloodhound::Matcher;
/// let invalid = Matcher::items::<String>().map(|node| node.value.push('!'));
/// ```
/// ```compile_fail
/// use binary_bloodhound::Matcher;
/// let invalid = Matcher::items::<String>().map(|node| node.value.into_bytes());
/// ```
///
/// Borrowed source values and captured data may live for the matcher's scope:
/// ```
/// use binary_bloodhound::Matcher;
/// let prefix = String::from("prefix:");
/// let stage = Matcher::new::<&str>()
///     .map(|node| (*node.value).strip_prefix(prefix.as_str()).unwrap_or(*node.value));
/// ```
///
/// Borrowing a node cannot escape a callback:
/// ```compile_fail
/// use binary_bloodhound::Matcher;
/// let invalid = Matcher::items::<String>().map(|node| node.value.as_str());
/// ```
/// Context access remains explicit and one-shot:
/// ```compile_fail
/// use binary_bloodhound::BinaryMatcher;
/// let invalid = BinaryMatcher::address(0x1000).map(|node, ctx| node);
/// ```
/// ```compile_fail
/// use binary_bloodhound::BinaryMatcher;
/// let invalid = BinaryMatcher::address(0x1000).with_context()
///     .map(|(ctx, _)| ctx.native());
/// ```
#[must_use = "matchers do nothing until run or resolved"]
pub struct Matcher<'scope, I, O, C: Cardinality = Variable, P = ()> {
    run: Arc<dyn Run<I, Trace<O, P>> + 'scope>,
    cardinality: PhantomData<C>,
}
impl<I, O, P, C: Cardinality> Clone for Matcher<'_, I, O, C, P> {
    fn clone(&self) -> Self {
        Self {
            run: Arc::clone(&self.run),
            cardinality: PhantomData,
        }
    }
}
impl<I, O, P, C: Cardinality> std::fmt::Display for Matcher<'_, I, O, C, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Matcher")
    }
}

impl<'scope, I: Send + 'scope, O: Send + Sync + 'scope, P: Send + Sync + 'scope, C: Cardinality>
    Matcher<'scope, I, O, C, P>
{
    pub(super) fn from_run(run: impl Run<I, Trace<O, P>> + 'scope) -> Self {
        Self {
            run: Arc::new(run),
            cardinality: PhantomData,
        }
    }

    pub(crate) fn transform_nodes<U, Q, D, F>(self, func: F) -> Matcher<'scope, I, U, D, Q>
    where
        U: Send + Sync + 'scope,
        Q: Send + Sync + 'scope,
        D: Cardinality,
        F: Fn((MatchContext<'_, '_>, Vec<Trace<O, P>>)) -> Result<Vec<Trace<U, Q>>>
            + Send
            + Sync
            + 'scope,
    {
        Matcher::from_run(Transform {
            matcher: self,
            func,
        })
    }
    pub(crate) async fn run_in(
        &self,
        input: I,
        ctx: MatchContext<'_, '_>,
    ) -> Result<Vec<Trace<O, P>>> {
        self.run.run(input, ctx).await
    }
    pub async fn run(&self, input: I, ctx: &AsyncContext<'_>) -> Result<C::Output<Trace<O, P>>> {
        self.run_resolved_in(input, MatchContext::new(ctx)).await
    }
    pub(crate) async fn run_resolved_in(
        &self,
        input: I,
        ctx: MatchContext<'_, '_>,
    ) -> Result<Resolved<O, P, C>> {
        C::finish(self.run_in(input, ctx).await?)
    }
    pub fn into_variable(self) -> Matcher<'scope, I, O, Variable, P> {
        Matcher {
            run: self.run,
            cardinality: PhantomData,
        }
    }
    pub fn with_context(self) -> WithContext<'scope, I, O, C, P> {
        WithContext { matcher: self }
    }

    /// Borrow each candidate; preserve order, duplicates, and cardinality.
    /// Each replacement retains the complete original node as parent.
    pub fn map<T: Send + Sync + 'scope, F>(self, func: F) -> Matcher<'scope, I, T, C, Trace<O, P>>
    where
        F: Fn(&Trace<O, P>) -> T + Send + Sync + 'scope,
    {
        self.try_map(move |node| Ok(func(node)))
    }
    pub fn try_map<T: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, C, Trace<O, P>>
    where
        F: Fn(&Trace<O, P>) -> Result<T> + Send + Sync + 'scope,
    {
        self.with_context().try_map(move |(_, node)| func(node))
    }
    /// Drop None replacements; retain the parent of each surviving value.
    pub fn map_filter<T: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, Variable, Trace<O, P>>
    where
        F: Fn(&Trace<O, P>) -> Option<T> + Send + Sync + 'scope,
    {
        self.try_map_filter(move |node| Ok(func(node)))
    }
    pub fn try_map_filter<T: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, Variable, Trace<O, P>>
    where
        F: Fn(&Trace<O, P>) -> Result<Option<T>> + Send + Sync + 'scope,
    {
        self.with_context()
            .try_map_filter(move |(_, node)| func(node))
    }
    pub fn filter_modify<T: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, Variable, Trace<O, P>>
    where
        F: Fn(&Trace<O, P>) -> Result<Option<T>> + Send + Sync + 'scope,
    {
        self.try_map_filter(func)
    }
    /// Expand each candidate, sharing its parent node across all emitted children.
    pub fn expand<T: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, Variable, Trace<O, P>>
    where
        F: Fn(&Trace<O, P>) -> Vec<T> + Send + Sync + 'scope,
    {
        self.try_expand(move |node| Ok(func(node)))
    }
    pub fn try_expand<T: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, Variable, Trace<O, P>>
    where
        F: Fn(&Trace<O, P>) -> Result<Vec<T>> + Send + Sync + 'scope,
    {
        self.with_context().try_expand(move |(_, node)| func(node))
    }
    /// Retain original nodes and ancestry without adding a navigation step.
    pub fn filter<F>(self, predicate: F) -> Matcher<'scope, I, O, Variable, P>
    where
        F: Fn(&Trace<O, P>) -> bool + Send + Sync + 'scope,
    {
        self.filter_each(predicate)
    }
    pub fn filter_each<F>(self, predicate: F) -> Matcher<'scope, I, O, Variable, P>
    where
        F: Fn(&Trace<O, P>) -> bool + Send + Sync + 'scope,
    {
        self.try_filter(move |node| Ok(predicate(node)))
    }
    pub fn try_filter<F>(self, predicate: F) -> Matcher<'scope, I, O, Variable, P>
    where
        F: Fn(&Trace<O, P>) -> Result<bool> + Send + Sync + 'scope,
    {
        self.with_context()
            .try_filter(move |(_, node)| predicate(node))
    }

    /// Borrow the resolved output and retain it as the new candidate's parent.
    /// Runs even on empty Variable output.
    pub fn transform<T: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, ExactlyOne, C::Output<Trace<O, P>>>
    where
        C::Output<Trace<O, P>>: Sync,
        F: Fn(&C::Output<Trace<O, P>>) -> T + Send + Sync + 'scope,
    {
        self.try_transform(move |nodes| Ok(func(nodes)))
    }
    pub fn try_transform<T: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, ExactlyOne, C::Output<Trace<O, P>>>
    where
        C::Output<Trace<O, P>>: Sync,
        F: Fn(&C::Output<Trace<O, P>>) -> Result<T> + Send + Sync + 'scope,
    {
        self.with_context()
            .try_transform(move |(_, nodes)| func(nodes))
    }
    /// Borrow the full collection; each result retains all input nodes as parent.
    pub fn transform_all<T: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, Variable, Vec<Trace<O, P>>>
    where
        F: Fn(&[Trace<O, P>]) -> Vec<T> + Send + Sync + 'scope,
    {
        self.try_transform_all(move |nodes| Ok(func(nodes)))
    }
    pub fn try_transform_all<T: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, Variable, Vec<Trace<O, P>>>
    where
        F: Fn(&[Trace<O, P>]) -> Result<Vec<T>> + Send + Sync + 'scope,
    {
        self.with_context()
            .try_transform_all(move |(_, nodes)| func(nodes))
    }

    /// Select an original node: 0 is first, -1 last. Invalid indices error safely,
    /// including isize::MIN. Evaluates all upstream candidates before selecting.
    pub fn at_index(self, index: isize) -> Matcher<'scope, I, O, ExactlyOne, P> {
        self.transform_nodes(move |(_, items)| {
            let len = items.len();
            let position = if index < 0 {
                len.checked_sub(index.unsigned_abs())
            } else {
                usize::try_from(index).ok()
            };
            position
                .filter(|position| *position < len)
                .and_then(|position| items.into_iter().nth(position))
                .map(|item| vec![item])
                .ok_or_else(|| {
                    ResolveError::new_msg(format!(
                        "candidate index {index} out of range for {len} candidates"
                    ))
                })
        })
    }
    pub fn first(self) -> Matcher<'scope, I, O, ExactlyOne, P> {
        self.at_index(0)
    }
    pub fn last(self) -> Matcher<'scope, I, O, ExactlyOne, P> {
        self.at_index(-1)
    }
    /// Require one unique current value, merging every contributing parent.
    /// Native empty/conflicting-value errors do not require Debug on ancestors.
    pub fn ensure_one(self) -> Matcher<'scope, I, O, ExactlyOne, P>
    where
        O: Debug + PartialEq,
    {
        self.transform_nodes(|(_, nodes)| {
            patternsleuth::resolvers::ensure_one(nodes.iter().map(|node| node.value.as_ref()))?;
            Ok(merge_items(nodes))
        })
    }

    /// Pass resolved nodes to the next stage. Retain both its ancestry and the
    /// upstream output through Composition, without cloning underlying values.
    pub fn then<T: Send + Sync + 'scope, Q: Send + Sync + 'scope, D: Cardinality>(
        self,
        next: Matcher<'scope, C::Output<Trace<O, P>>, T, D, Q>,
    ) -> Matcher<'scope, I, T, D, SequenceParents<O, P, C, Q>>
    where
        C::Output<Trace<O, P>>: Clone + Sync,
    {
        Matcher::from_run(Then { first: self, next })
    }

    pub fn fork<T: Send + Sync + 'scope, Q: Send + Sync + 'scope, D: Cardinality>(
        self,
        right: Matcher<'scope, I, T, D, Q>,
    ) -> ForkMatcher<'scope, I, Trace<O, P>, Trace<T, Q>, C, D>
    where
        I: Clone,
        C::Output<Trace<O, P>>: Sync,
        D::Output<Trace<T, Q>>: Sync,
    {
        Matcher::from_run(Fork { left: self, right })
    }

    /// Borrow each candidate to build an inner matcher. Evaluate sequentially in
    /// the current image and bounds, retaining outer and inner derivations.
    ///
    /// ```
    /// use binary_bloodhound::BinaryMatcher;
    /// let matcher = BinaryMatcher::address(0x1000).flat_map(|node| {
    ///     BinaryMatcher::address(*node.value + 4).root_functions()
    /// });
    /// ```
    /// ```compile_fail
    /// use binary_bloodhound::BinaryMatcher;
    /// let invalid = BinaryMatcher::address(0x1000).flat_map(|node| vec![*node.value]);
    /// ```
    pub fn flat_map<T, Q, D, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, Variable, Composition<Trace<O, P>, Q>>
    where
        T: Send + Sync + 'scope,
        Q: Send + Sync + 'scope,
        D: Cardinality,
        F: Fn(&Trace<O, P>) -> Matcher<'scope, (), T, D, Q> + Send + Sync + 'scope,
    {
        self.try_flat_map(move |node| Ok(func(node)))
    }
    pub fn try_flat_map<T, Q, D, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, T, Variable, Composition<Trace<O, P>, Q>>
    where
        T: Send + Sync + 'scope,
        Q: Send + Sync + 'scope,
        D: Cardinality,
        F: Fn(&Trace<O, P>) -> Result<Matcher<'scope, (), T, D, Q>> + Send + Sync + 'scope,
    {
        self.with_context()
            .try_flat_map(move |(_, node)| func(node))
    }
}

impl<'scope, O: Send + Sync + 'scope, P: Send + Sync + 'scope, C: Cardinality>
    Matcher<'scope, (), O, C, P>
{
    pub async fn resolve(&self, ctx: &AsyncContext<'_>) -> Result<C::Output<Trace<O, P>>> {
        self.run((), ctx).await
    }
}
