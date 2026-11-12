use std::sync::Arc;

use futures::future::BoxFuture;
use patternsleuth::resolvers::Result;

use crate::{Cardinality, Contributor, MatchContext, Matcher, Trace, Variable, pipeline::Run};

pub(crate) fn merge_items<T: PartialEq, P>(nodes: Vec<Trace<T, P>>) -> Vec<Trace<T, P>> {
    let mut result = Vec::new();
    merge_into(&mut result, nodes);
    result
}

fn merge_into<T: PartialEq, P>(result: &mut Vec<Trace<T, P>>, nodes: Vec<Trace<T, P>>) {
    for node in nodes {
        if let Some(previous) = result
            .iter_mut()
            .find(|previous| previous.value == node.value)
        {
            previous.merge(node);
        } else {
            result.push(node);
        }
    }
}

enum SetOperation {
    Union,
    Intersect,
}

struct SetAll<'scope, I, T, P> {
    matchers: Vec<Matcher<'scope, I, T, Variable, P>>,
    operation: SetOperation,
}
impl<'scope, I: Clone + Send + 'scope, T: PartialEq + Send + Sync + 'scope, P: Send + Sync + 'scope>
    Run<I, Trace<T, P>> for SetAll<'scope, I, T, P>
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<Trace<T, P>>>>
    where
        I: 'ctx,
        Trace<T, P>: 'ctx,
    {
        Box::pin(async move {
            let mut result: Vec<Trace<T, P>> = Vec::new();
            for (index, matcher) in self.matchers.iter().enumerate() {
                let nodes = matcher.run_in(input.clone(), ctx).await?;
                if matches!(self.operation, SetOperation::Intersect) && index > 0 {
                    let mut nodes = merge_items(nodes);
                    result = result
                        .into_iter()
                        .filter_map(|mut node| {
                            let position =
                                nodes.iter().position(|other| other.value == node.value)?;
                            node.merge(nodes.remove(position));
                            Some(node)
                        })
                        .collect();
                } else {
                    merge_into(&mut result, nodes);
                }
            }
            Ok(result)
        })
    }
}

impl<'scope, I: Send + 'scope, O: Send + Sync + 'scope, P: Send + Sync + 'scope, C: Cardinality>
    Matcher<'scope, I, O, C, P>
{
    /// Stable sequential union. Compare values, retaining typed Left/Right parents
    /// from both branches. Stop on the first error. Ancestry types may differ.
    pub fn union<Q: Send + Sync + 'scope, D: Cardinality>(
        self,
        other: Matcher<'scope, I, O, D, Q>,
    ) -> Matcher<'scope, I, O, Variable, Contributor<P, Q>>
    where
        I: Clone,
        O: PartialEq,
    {
        self.set_with(other, SetOperation::Union)
    }

    /// Stable sequential intersection, retaining all contributors to common values.
    /// Later branch errors propagate even when the intersection is already empty.
    pub fn intersect<Q: Send + Sync + 'scope, D: Cardinality>(
        self,
        other: Matcher<'scope, I, O, D, Q>,
    ) -> Matcher<'scope, I, O, Variable, Contributor<P, Q>>
    where
        I: Clone,
        O: PartialEq,
    {
        self.set_with(other, SetOperation::Intersect)
    }

    fn set_with<Q: Send + Sync + 'scope, D: Cardinality>(
        self,
        other: Matcher<'scope, I, O, D, Q>,
        operation: SetOperation,
    ) -> Matcher<'scope, I, O, Variable, Contributor<P, Q>>
    where
        I: Clone,
        O: PartialEq,
    {
        let left = self.map_parents(Contributor::Left).into_variable();
        let right = other.map_parents(Contributor::Right).into_variable();
        Matcher::set_all([left, right], operation)
    }

    fn map_parents<Q: Send + Sync + 'scope, F>(self, func: F) -> Matcher<'scope, I, O, C, Q>
    where
        F: Fn(Arc<P>) -> Q + Send + Sync + 'scope,
    {
        self.transform_nodes(move |(_, nodes)| {
            Ok(nodes
                .into_iter()
                .map(|node| node.map_parents(&func))
                .collect())
        })
    }

    pub fn union_all(matchers: impl IntoIterator<Item = Self>) -> Matcher<'scope, I, O, Variable, P>
    where
        I: Clone,
        O: PartialEq,
    {
        Self::set_all(matchers, SetOperation::Union)
    }

    pub fn intersect_all(
        matchers: impl IntoIterator<Item = Self>,
    ) -> Matcher<'scope, I, O, Variable, P>
    where
        I: Clone,
        O: PartialEq,
    {
        Self::set_all(matchers, SetOperation::Intersect)
    }

    fn set_all(
        matchers: impl IntoIterator<Item = Self>,
        operation: SetOperation,
    ) -> Matcher<'scope, I, O, Variable, P>
    where
        I: Clone,
        O: PartialEq,
    {
        Matcher::from_run(SetAll {
            matchers: matchers.into_iter().map(Self::into_variable).collect(),
            operation,
        })
    }
}
