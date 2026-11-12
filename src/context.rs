use std::sync::Arc;

use patternsleuth::resolvers::Result;

use crate::{Cardinality, ExactlyOne, MatchContext, Matcher, Trace, Variable};

/// One-shot context adapter; callbacks still borrow immutable candidates.
#[must_use = "with_context applies only when followed by a transformation"]
pub struct WithContext<'scope, I, O, C: Cardinality = Variable, P = ()> {
    pub(super) matcher: Matcher<'scope, I, O, C, P>,
}
impl<'scope, I: Send + 'scope, O: Send + Sync + 'scope, P: Send + Sync + 'scope, C: Cardinality>
    WithContext<'scope, I, O, C, P>
{
    pub fn map<U: Send + Sync + 'scope, F>(self, func: F) -> Matcher<'scope, I, U, C, Trace<O, P>>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> U + Send + Sync + 'scope,
    {
        self.try_map(move |input| Ok(func(input)))
    }
    pub fn try_map<U: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, C, Trace<O, P>>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Result<U> + Send + Sync + 'scope,
    {
        self.try_expand_values(move |input| Ok([func(input)?]))
    }
    pub fn map_filter<U: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, Variable, Trace<O, P>>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Option<U> + Send + Sync + 'scope,
    {
        self.try_map_filter(move |input| Ok(func(input)))
    }
    pub fn try_map_filter<U: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, Variable, Trace<O, P>>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Result<Option<U>> + Send + Sync + 'scope,
    {
        self.try_expand_values(func)
    }
    pub fn filter_modify<U: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, Variable, Trace<O, P>>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Result<Option<U>> + Send + Sync + 'scope,
    {
        self.try_map_filter(func)
    }
    pub fn expand<U: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, Variable, Trace<O, P>>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Vec<U> + Send + Sync + 'scope,
    {
        self.try_expand(move |input| Ok(func(input)))
    }
    pub fn try_expand<U: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, Variable, Trace<O, P>>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Result<Vec<U>> + Send + Sync + 'scope,
    {
        self.try_expand_values(func)
    }

    fn try_expand_values<U, D, V, F>(self, func: F) -> Matcher<'scope, I, U, D, Trace<O, P>>
    where
        U: Send + Sync + 'scope,
        D: Cardinality,
        V: IntoIterator<Item = U>,
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Result<V> + Send + Sync + 'scope,
    {
        self.matcher.transform_nodes(move |(ctx, nodes)| {
            let mut result = Vec::new();
            for node in nodes {
                let values = func((ctx, &node))?;
                result.extend(Trace::children(values, node));
            }
            Ok(result)
        })
    }
    pub fn filter<F>(self, predicate: F) -> Matcher<'scope, I, O, Variable, P>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> bool + Send + Sync + 'scope,
    {
        self.filter_each(predicate)
    }
    pub fn filter_each<F>(self, predicate: F) -> Matcher<'scope, I, O, Variable, P>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> bool + Send + Sync + 'scope,
    {
        self.try_filter(move |input| Ok(predicate(input)))
    }
    pub fn try_filter<F>(self, predicate: F) -> Matcher<'scope, I, O, Variable, P>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<O, P>)) -> Result<bool> + Send + Sync + 'scope,
    {
        self.matcher.transform_nodes(move |(ctx, nodes)| {
            nodes
                .into_iter()
                .filter_map(|node| match predicate((ctx, &node)) {
                    Ok(true) => Some(Ok(node)),
                    Ok(false) => None,
                    Err(error) => Some(Err(error)),
                })
                .collect()
        })
    }
    pub fn transform<U: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, ExactlyOne, C::Output<Trace<O, P>>>
    where
        C::Output<Trace<O, P>>: Sync,
        F: Fn((MatchContext<'_, '_>, &C::Output<Trace<O, P>>)) -> U + Send + Sync + 'scope,
    {
        self.try_transform(move |input| Ok(func(input)))
    }
    pub fn try_transform<U: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, ExactlyOne, C::Output<Trace<O, P>>>
    where
        C::Output<Trace<O, P>>: Sync,
        F: Fn((MatchContext<'_, '_>, &C::Output<Trace<O, P>>)) -> Result<U> + Send + Sync + 'scope,
    {
        self.matcher.transform_nodes(move |(ctx, nodes)| {
            let parent = C::finish(nodes)?;
            let value = func((ctx, &parent))?;
            Ok(vec![Trace::child(value, Arc::new(parent))])
        })
    }
    pub fn transform_all<U: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, Variable, Vec<Trace<O, P>>>
    where
        F: Fn((MatchContext<'_, '_>, &[Trace<O, P>])) -> Vec<U> + Send + Sync + 'scope,
    {
        self.try_transform_all(move |input| Ok(func(input)))
    }
    pub fn try_transform_all<U: Send + Sync + 'scope, F>(
        self,
        func: F,
    ) -> Matcher<'scope, I, U, Variable, Vec<Trace<O, P>>>
    where
        F: Fn((MatchContext<'_, '_>, &[Trace<O, P>])) -> Result<Vec<U>> + Send + Sync + 'scope,
    {
        self.matcher.transform_nodes(move |(ctx, nodes)| {
            let values = func((ctx, &nodes))?;
            Ok(Trace::children(values, nodes).collect())
        })
    }
}

impl<'scope, I: Send + 'scope, P: Send + Sync + 'scope, C: Cardinality>
    WithContext<'scope, I, u64, C, P>
{
    pub fn modify_with<F>(self, func: F) -> Matcher<'scope, I, u64, C, Trace<u64, P>>
    where
        F: Fn((MatchContext<'_, '_>, &Trace<u64, P>)) -> Result<u64> + Send + Sync + 'scope,
    {
        self.try_map(func)
    }
}
