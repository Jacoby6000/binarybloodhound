use std::sync::Arc;

use futures::future::BoxFuture;
use patternsleuth::resolvers::Result;

use crate::{
    Cardinality, Composition, ExactlyOne, MatchContext, Matcher, Resolved, Trace, Variable,
    WithContext, pipeline::Run,
};

pub type ForkOutput<O, T, C, D> = (<C as Cardinality>::Output<O>, <D as Cardinality>::Output<T>);

/// Upstream resolved nodes and an inner contributor from then composition.
pub type SequenceParents<O, P, C, Q> = Composition<Resolved<O, P, C>, Q>;
/// A fork's single result, retaining both branches as value and parent.
pub type ForkMatcher<'scope, I, L, R, C, D> =
    Matcher<'scope, I, ForkOutput<L, R, C, D>, ExactlyOne, ForkOutput<L, R, C, D>>;

type ForkTrace<L, R, C, D> = Trace<ForkOutput<L, R, C, D>, ForkOutput<L, R, C, D>>;

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
> Run<I, Trace<T, SequenceParents<O, P, C, Q>>> for Then<'scope, I, O, P, T, Q, C, D>
where
    C::Output<Trace<O, P>>: Clone + Sync,
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<Trace<T, SequenceParents<O, P, C, Q>>>>>
    where
        I: 'ctx,
        Trace<T, SequenceParents<O, P, C, Q>>: 'ctx,
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

struct FlatMap<'scope, I, O, P, C: Cardinality, F> {
    matcher: Matcher<'scope, I, O, C, P>,
    func: F,
}
impl<
    'scope,
    I: Send + 'scope,
    O: Send + Sync + 'scope,
    P: Send + Sync + 'scope,
    U: Send + Sync + 'scope,
    Q: Send + Sync + 'scope,
    C: Cardinality,
    D: Cardinality,
    F,
> Run<I, Trace<U, Composition<Trace<O, P>, Q>>> for FlatMap<'scope, I, O, P, C, F>
where
    F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Result<Matcher<'scope, (), U, D, Q>>
        + Send
        + Sync,
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<Trace<U, Composition<Trace<O, P>, Q>>>>>
    where
        I: 'ctx,
        Trace<U, Composition<Trace<O, P>, Q>>: 'ctx,
    {
        Box::pin(async move {
            let mut result = Vec::new();
            for node in self.matcher.run_in(input, ctx).await? {
                let parent = Arc::new(node);
                let matcher = (self.func)((ctx, &parent))?;
                let nodes = D::into_items(matcher.run_resolved_in((), ctx).await?);
                result.extend(
                    nodes
                        .into_iter()
                        .map(|node| node.compose(Arc::clone(&parent))),
                );
            }
            Ok(result)
        })
    }
}

impl<'scope, I: Send + 'scope, O: Send + Sync + 'scope, P: Send + Sync + 'scope, C: Cardinality>
    Matcher<'scope, I, O, C, P>
{
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

impl<'scope, I: Send + 'scope, O: Send + Sync + 'scope, P: Send + Sync + 'scope, C: Cardinality>
    WithContext<'scope, I, O, C, P>
{
    pub fn flat_map<U, Q, D, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, Variable, Composition<Trace<O, P>, Q>>
    where
        U: Send + Sync + 'scope,
        Q: Send + Sync + 'scope,
        D: Cardinality,
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Matcher<'scope, (), U, D, Q>
            + Send
            + Sync
            + 'scope,
    {
        self.try_flat_map(move |input| Ok(func(input)))
    }

    pub fn try_flat_map<U, Q, D, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, Variable, Composition<Trace<O, P>, Q>>
    where
        U: Send + Sync + 'scope,
        Q: Send + Sync + 'scope,
        D: Cardinality,
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Result<Matcher<'scope, (), U, D, Q>>
            + Send
            + Sync
            + 'scope,
    {
        Matcher::from_run(FlatMap {
            matcher: self.matcher,
            func,
        })
    }
}
