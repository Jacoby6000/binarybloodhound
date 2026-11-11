use std::sync::Arc;

use futures::future::{BoxFuture, join_all};
use patternsleuth::{
    resolvers::{ResolveError, Result},
    scanner::Pattern,
};

use crate::{BinaryMatcher, ExactlyOne, MatchContext, Matcher, Trace, Variable, pipeline::Run};

struct AsyncSource<F>(F);
impl<I: Send, O: Send + Sync, F> Run<I, Trace<O>> for AsyncSource<F>
where
    F: for<'ctx, 'image> Fn(I, MatchContext<'ctx, 'image>) -> BoxFuture<'ctx, Result<Vec<O>>>
        + Send
        + Sync,
{
    fn run<'ctx, 'image>(
        &'ctx self,
        input: I,
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<Trace<O>>>>
    where
        I: 'ctx,
        Trace<O>: 'ctx,
    {
        Box::pin(async move {
            Ok((self.0)(input, ctx)
                .await?
                .into_iter()
                .map(Trace::root)
                .collect())
        })
    }
}

struct SyncStage<F>(F);
impl<I: Send, O: Send, F> Run<I, O> for SyncStage<F>
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

impl<'scope, I: Send + 'scope, O: Send + Sync + 'scope> Matcher<'scope, I, O> {
    pub fn from_async<F>(run: F) -> Self
    where
        F: for<'ctx, 'image> Fn(I, MatchContext<'ctx, 'image>) -> BoxFuture<'ctx, Result<Vec<O>>>
            + Send
            + Sync
            + 'scope,
    {
        Self::from_run(AsyncSource(run))
    }

    /// Produce source values; evaluation wraps each with a unit parent.
    pub fn from_sync<F>(run: F) -> Self
    where
        F: Fn(I) -> Result<Vec<O>> + Send + Sync + 'scope,
    {
        Self::from_run(SyncStage(move |input| {
            Ok(run(input)?.into_iter().map(Trace::root).collect())
        }))
    }
}

impl<'scope, T: Send + Sync + 'scope> Matcher<'scope, Vec<T>, T> {
    pub fn identity() -> Self {
        Self::from_sync(Ok)
    }
}

impl<'scope, I: Send + 'scope, O: Send + Sync + 'scope> Matcher<'scope, I, O, ExactlyOne> {
    pub fn from_value<F>(run: F) -> Self
    where
        F: Fn(I) -> Result<O> + Send + Sync + 'scope,
    {
        Self::from_run(SyncStage(move |input| Ok(vec![Trace::root(run(input)?)])))
    }
}

impl<'scope> Matcher<'scope, (), ()> {
    /// Reuse existing candidates without restarting their ancestry.
    pub fn nodes<T: Send + Sync + 'scope, P: Send + Sync + 'scope>()
    -> Matcher<'scope, Vec<Trace<T, P>>, T, Variable, P> {
        Matcher::from_run(SyncStage(Ok))
    }

    pub fn items<T: Send + Sync + 'scope>() -> Matcher<'scope, Vec<T>, T> {
        Matcher::from_sync(Ok)
    }

    #[allow(clippy::new_ret_no_self)]
    pub fn new<T: Send + Sync + 'scope>() -> Matcher<'scope, T, T, ExactlyOne> {
        Matcher::from_value(Ok)
    }
}

impl<'scope, O: Send + Sync + 'scope, P: Send + Sync + 'scope> Matcher<'scope, (), O, Variable, P> {
    /// Reuse resolved immutable nodes, preserving their complete ancestry.
    pub fn from_nodes(nodes: impl AsRef<[Trace<O, P>]>) -> Self {
        let nodes = nodes.as_ref().to_vec();
        Self::from_run(SyncStage(move |()| Ok(nodes.clone())))
    }
}

/// A parsed pattern or signature accepted by BinaryMatcher::patterns.
pub trait IntoPattern {
    fn into_pattern(self) -> Result<Pattern>;
}

impl IntoPattern for Pattern {
    fn into_pattern(self) -> Result<Pattern> {
        Ok(self)
    }
}
impl IntoPattern for &Pattern {
    fn into_pattern(self) -> Result<Pattern> {
        Ok(self.clone())
    }
}
impl IntoPattern for &str {
    fn into_pattern(self) -> Result<Pattern> {
        parse_signature(self)
    }
}
impl IntoPattern for String {
    fn into_pattern(self) -> Result<Pattern> {
        parse_signature(self)
    }
}
impl IntoPattern for &String {
    fn into_pattern(self) -> Result<Pattern> {
        parse_signature(self)
    }
}
impl IntoPattern for &&str {
    fn into_pattern(self) -> Result<Pattern> {
        parse_signature(self)
    }
}

fn parse_signature(signature: impl AsRef<str>) -> Result<Pattern> {
    Pattern::new(signature).map_err(|error| ResolveError::new_msg(format!("{error:#}")))
}

impl<'scope> BinaryMatcher<'scope> {
    pub fn pattern(pattern: Pattern) -> Self {
        Self::scan_patterns(vec![pattern])
    }

    /// Parse once; submit scans together, preserving pattern order and duplicates.
    /// Invalid signatures report their zero-based index. Empty collections are valid.
    ///
    /// ```
    /// use binary_bloodhound::BinaryMatcher;
    /// let matcher = BinaryMatcher::patterns(["48 89 ?? ??", "E8 | ?? ?? ?? ??"])?;
    /// # Ok::<(), patternsleuth::resolvers::ResolveError>(())
    /// ```
    pub fn patterns<P: IntoPattern>(patterns: impl IntoIterator<Item = P>) -> Result<Self> {
        let patterns = patterns
            .into_iter()
            .enumerate()
            .map(|(index, pattern)| {
                pattern.into_pattern().map_err(|error| {
                    ResolveError::new_msg(format!("invalid pattern at index {index}: {error}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::scan_patterns(patterns))
    }

    fn scan_patterns(patterns: Vec<Pattern>) -> Self {
        let patterns = Arc::new(patterns);
        Self::from_async(move |(), ctx| {
            let patterns = Arc::clone(&patterns);
            Box::pin(async move {
                let results =
                    join_all(patterns.iter().map(|pattern| ctx.scan(pattern.clone()))).await;
                Ok(results.into_iter().flatten().collect())
            })
        })
    }

    /// Produce an address without checking image bounds.
    pub fn address(address: u64) -> Self {
        Self::candidates([address])
    }

    /// Copy supplied addresses. Preserve order and duplicates; empty/unmapped inputs are valid.
    /// Every source node starts with a unit parent.
    pub fn candidates(addresses: impl AsRef<[u64]>) -> Self {
        let addresses = addresses.as_ref().to_vec();
        Self::from_sync(move |()| Ok(addresses.clone()))
    }
}
