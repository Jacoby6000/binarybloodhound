use std::sync::Arc;

use futures::future::{BoxFuture, join_all};
use patternsleuth::{
    resolvers::{ResolveError, Result},
    scanner::Pattern,
};

use crate::{
    BinaryMatcher, ExactlyOne, MatchContext, Matcher, PatternMatch, Trace, Variable, pipeline::Run,
};

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

struct CapturedPatterns<Tag> {
    patterns: Vec<(Arc<Tag>, Arc<Pattern>)>,
}

impl<Tag: Send + Sync> Run<(), Trace<PatternMatch<Tag>>> for CapturedPatterns<Tag> {
    fn run<'ctx, 'image>(
        &'ctx self,
        (): (),
        ctx: MatchContext<'ctx, 'image>,
    ) -> BoxFuture<'ctx, Result<Vec<Trace<PatternMatch<Tag>>>>>
    where
        (): 'ctx,
        Trace<PatternMatch<Tag>>: 'ctx,
    {
        Box::pin(async move {
            let results = join_all(
                self.patterns
                    .iter()
                    .map(|(_, pattern)| ctx.scan(pattern.as_ref().clone())),
            )
            .await;
            let mut matches = Vec::new();
            for ((tag, pattern), addresses) in self.patterns.iter().zip(results) {
                for address in addresses {
                    matches.push(Trace::root(PatternMatch::read(
                        ctx.image(),
                        address,
                        Arc::clone(pattern),
                        Arc::clone(tag),
                    )?));
                }
            }
            Ok(matches)
        })
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

fn parse_indexed_pattern(index: usize, pattern: impl IntoPattern) -> Result<Pattern> {
    pattern.into_pattern().map_err(|error| {
        ResolveError::new_msg(format!("invalid pattern at index {index}: {error}"))
    })
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
            .map(|(index, pattern)| parse_indexed_pattern(index, pattern))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::scan_patterns(patterns))
    }

    /// Scan patterns with owned capture bytes and shared pattern metadata.
    /// Preserve pattern order, match order, and duplicates. Scan and copy captures
    /// before downstream callbacks run; complete patterns must fit active bounds.
    ///
    /// ```
    /// use binary_bloodhound::BinaryMatcher;
    /// let matcher = BinaryMatcher::capture_patterns(["E8 [ ?? ?? ?? ?? ]"])?
    ///     .try_map(|node| node.captures[0].rip4());
    /// # Ok::<(), patternsleuth::resolvers::ResolveError>(())
    /// ```
    pub fn capture_patterns<P: IntoPattern>(
        patterns: impl IntoIterator<Item = P>,
    ) -> Result<Matcher<'scope, (), PatternMatch>> {
        Self::tagged_capture_patterns(patterns.into_iter().map(|pattern| ((), pattern)))
    }

    /// Capture-aware sources with user tags. Parse once, reporting invalid
    /// signatures by zero-based index. Tags may be borrowed and need not be Clone.
    /// Captures are owned snapshots, so they can escape the image's lifetime.
    pub fn tagged_capture_patterns<Tag: Send + Sync + 'scope, P: IntoPattern>(
        patterns: impl IntoIterator<Item = (Tag, P)>,
    ) -> Result<Matcher<'scope, (), PatternMatch<Tag>>> {
        let patterns = patterns
            .into_iter()
            .enumerate()
            .map(|(index, (tag, pattern))| {
                Ok((
                    Arc::new(tag),
                    Arc::new(parse_indexed_pattern(index, pattern)?),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Matcher::from_run(CapturedPatterns { patterns }))
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
