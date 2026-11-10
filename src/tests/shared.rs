use super::*;
use object::SectionKind;
use patternsleuth::{
    NamedMemorySection,
    image::Image,
    resolvers::{Context as _, bail_out, eval},
};

fn section(
    name: &str,
    address: u64,
    kind: SectionKind,
    data: Vec<u8>,
) -> NamedMemorySection<'static> {
    NamedMemorySection::new(name.into(), address, kind, data)
}

fn image(text: Vec<u8>) -> Image<'static> {
    construct_image(text, 2)
}

fn run<T: HasAddress + Send>(
    image: &Image<'_>,
    matcher: Matcher<'_, (), Vec<T>>,
) -> Result<Vec<u64>> {
    eval(image, move |ctx| {
        Box::pin(async move { matcher.addresses().resolve(ctx).await })
    })
}

fn patterns<'scope>(values: &[&str]) -> BinaryMatcher<'scope> {
    BinaryMatcher::patterns(values).unwrap()
}

fn run_stage<I, O>(image: &Image<'_>, matcher: Matcher<I, O>, input: I) -> Result<O>
where
    I: Send + Sync,
    O: Send + Sync,
{
    eval(image, move |ctx| {
        Box::pin(async move { matcher.run(input, ctx).await })
    })
}

#[test]
fn matchers_compose_directly_with_native_resolver_results() {
    fn build<'scope>() -> patternsleuth::resolvers::Result<Matcher<'scope, (), u64>> {
        Ok(BinaryMatcher::patterns(["AA DD CC", "AA DD CC"])?
            .try_map(patternsleuth::resolvers::ensure_one))
    }
    let result: patternsleuth::resolvers::Result<u64> =
        run_stage(&scan_image(), build().unwrap(), ());
    assert_eq!(result.unwrap(), TEXT + 24);

    let ambiguous = BinaryMatcher::patterns(["AA BB CC"])
        .unwrap()
        .try_map(patternsleuth::resolvers::ensure_one);
    assert_eq!(
        run_stage(&scan_image(), ambiguous, ()).unwrap_err(),
        patternsleuth::resolvers::ensure_one([TEXT + 8, TARGET]).unwrap_err()
    );
}

#[test]
fn matcher_callbacks_preserve_native_error_variants_without_conversion() {
    fn reject(_: Vec<u64>) -> patternsleuth::resolvers::Result<Vec<u64>> {
        Err(patternsleuth::MemoryAccessError::MisalginedAddress(TEXT, TEXT + 8).into())
    }

    let matcher = BinaryMatcher::address(TEXT)
        .try_map(reject)
        .first()
        .xrefs()
        .addresses()
        .with_context()
        .sub(|_| panic!("native error must skip subsequent callbacks"));
    assert_eq!(
        run(&scan_image(), matcher).unwrap_err(),
        ResolveError::from(patternsleuth::MemoryAccessError::MisalginedAddress(
            TEXT,
            TEXT + 8
        ))
    );
}

#[test]
fn new_passes_non_clone_input_and_infers_transformed_output() {
    struct Input {
        addresses: Vec<u64>,
    }

    let stage = Matcher::new::<Input>()
        .map(|input| input.addresses)
        .map(|addresses| addresses.len());
    assert_eq!(
        run_stage(
            &scan_image(),
            stage,
            Input {
                addresses: vec![TEXT, TARGET]
            }
        )
        .unwrap(),
        2
    );
}

#[test]
fn from_sync_infers_types_and_accepts_borrowed_inputs_outputs_and_captures() {
    let text = String::from("prefix:payload");
    let prefix = String::from("prefix:");
    let stage =
        Matcher::from_sync(|value: &str| Ok(value.strip_prefix(prefix.as_str()).unwrap_or(value)));
    assert_eq!(
        run_stage(&scan_image(), stage, text.as_str()).unwrap(),
        "payload"
    );
}

#[test]
fn from_sync_preserves_native_errors_and_skips_subsequent_stages() {
    let stage = Matcher::from_sync(|_: Vec<u64>| -> Result<Vec<u64>> {
        Err(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError.into())
    });
    let matcher = BinaryMatcher::address(TEXT)
        .then(stage)
        .map(|_| panic!("callback must not run after an error"));
    assert_eq!(
        run_stage(&scan_image(), matcher, ()).unwrap_err(),
        ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
    );
}

#[test]
fn stages_accept_borrowed_inputs_outputs_and_captures() {
    let text = String::from("prefix:payload");
    let prefix = String::from("prefix:");
    let stage = Matcher::new::<&str>().map(|value| value.strip_prefix(prefix.as_str()).unwrap());
    let result = run_stage(&scan_image(), stage, text.as_str()).unwrap();
    assert_eq!(result, "payload");
    assert_eq!(result.as_ptr(), text[prefix.len()..].as_ptr());
}

#[test]
fn borrowed_outputs_survive_a_shorter_evaluation_context() {
    let text = String::from("borrowed result");
    let result = {
        let image = scan_image();
        let matcher = BinaryMatcher::address(TEXT).map(|_| text.as_str());
        eval(&image, move |ctx| {
            Box::pin(async move { matcher.resolve(ctx).await })
        })
        .unwrap()
    };
    assert_eq!(result, text);
}

#[test]
fn from_async_can_read_image_memory() {
    use patternsleuth::MemoryTrait;

    let matcher = Matcher::from_async(|address, ctx| {
        Box::pin(async move { Ok(ctx.image().memory.u8(address)?) })
    });
    let result = run_stage(&scan_image(), matcher, TEXT + 8).unwrap();

    assert_eq!(result, 0xaa);
}

#[test]
fn fork_passes_the_same_input_to_both_branches() {
    let left = Matcher::new::<u64>().map(|value| value + 1);
    let right = Matcher::new::<u64>().map(|value| value * 2);
    let result = run_stage(&scan_image(), left.fork(right), 3).unwrap();

    assert_eq!(result, (4, 6));
}

#[test]
fn fork_skips_right_branch_after_left_error() {
    let left: Matcher<Vec<u64>, Vec<u64>> =
        Matcher::identity().try_map(|_| Err(ResolveError::new_msg("left failed")));
    let right: Matcher<Vec<u64>, Vec<u64>> =
        Matcher::identity().map(|_| panic!("right must not run after left error"));
    let error = run_stage(&scan_image(), left.fork(right), vec![1]).unwrap_err();

    assert_eq!(error.to_string(), "left failed");
}

#[test]
fn fork_propagates_right_branch_errors() {
    let left: Matcher<Vec<u64>, Vec<u64>> = Matcher::identity();
    let right: Matcher<Vec<u64>, Vec<u64>> =
        Matcher::identity().try_map(|_| Err(ResolveError::new_msg("right failed")));
    let error = run_stage(&scan_image(), left.fork(right), vec![1]).unwrap_err();

    assert_eq!(error.to_string(), "right failed");
}

#[test]
fn union_keeps_first_occurrences_left_then_right() {
    let left = Matcher::from_sync(|()| Ok(vec![3, 1, 3]));
    let right = Matcher::from_sync(|()| Ok(vec![1, 2, 2]));
    let result = run(&scan_image(), left.union(right)).unwrap();

    assert_eq!(result, [3, 1, 2]);
}

#[test]
fn union_all_includes_each_branch_in_order() {
    let matchers = [3, 1, 2].into_iter().map(BinaryMatcher::address);
    let result = run(&scan_image(), BinaryMatcher::union_all(matchers)).unwrap();

    assert_eq!(result, [3, 1, 2]);
}

#[test]
fn set_operations_without_branches_return_empty_results() {
    let image = scan_image();
    let union = run(&image, BinaryMatcher::union_all([])).unwrap();
    let intersect = run(&image, BinaryMatcher::intersect_all([])).unwrap();

    assert!(union.is_empty());
    assert!(intersect.is_empty());
}

#[test]
fn intersect_keeps_first_common_occurrences_in_left_order() {
    let left = Matcher::from_sync(|()| Ok(vec![3, 1, 3, 2]));
    let right = Matcher::from_sync(|()| Ok(vec![2, 3, 3]));
    let result = run(&scan_image(), left.intersect(right)).unwrap();

    assert_eq!(result, [3, 2]);
}

#[test]
fn intersect_all_requires_items_in_every_branch() {
    let first = Matcher::from_sync(|()| Ok(vec![3, 1, 2]));
    let second = Matcher::from_sync(|()| Ok(vec![2, 3]));
    let third = BinaryMatcher::address(3);
    let matcher = BinaryMatcher::intersect_all([first, second, third]);
    let result = run(&scan_image(), matcher).unwrap();

    assert_eq!(result, [3]);
}

#[test]
fn intersect_all_propagates_errors_even_after_an_empty_result() {
    let empty = Matcher::from_sync(|()| Ok(Vec::new()));
    let failing = Matcher::from_sync(|()| Err(ResolveError::new_msg("branch failed")));
    let skipped = Matcher::from_sync(|()| panic!("must stop after error"));
    let matcher = BinaryMatcher::intersect_all([empty, failing, skipped]);
    let error = run(&scan_image(), matcher).unwrap_err();

    assert_eq!(error.to_string(), "branch failed");
}

#[test]
fn map_each_accepts_owned_items() {
    let matcher = Matcher::new::<Vec<String>>().map_each(|word| word.to_uppercase());
    let result = run_stage(&scan_image(), matcher, vec!["foo".into()]).unwrap();

    assert_eq!(result, ["FOO"]);
}

#[test]
fn context_map_can_read_image_memory() {
    use patternsleuth::MemoryTrait;

    let matcher = BinaryMatcher::address(TEXT + 8)
        .with_context()
        .try_map(|(ctx, addresses)| Ok(ctx.image().memory.u8(addresses[0])?));
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, 0xaa);
}

#[test]
fn context_combinators_use_each_runs_image_instead_of_capturing_one() {
    use patternsleuth::MemoryTrait;

    let matcher = BinaryMatcher::address(TEXT + 8)
        .with_context()
        .try_map_each(|(ctx, address)| Ok(ctx.image().memory.u8(address)?));
    let first = scan_image();
    let second = scan_image();
    let mut text = second.memory.sections()[0].data().to_vec();
    text[8] = 0xbb;
    let second = second.with_text(text).unwrap();
    assert_eq!(run_stage(&first, matcher.clone(), ()).unwrap(), [0xaa]);
    assert_eq!(run_stage(&second, matcher, ()).unwrap(), [0xbb]);
}

#[test]
fn context_map_each_skips_empty_input() {
    let stage: Matcher<Vec<u64>, Vec<u64>> = Matcher::identity()
        .with_context()
        .try_map_each(|_| panic!("empty input must skip the callback"));
    let result = run_stage(&scan_image(), stage, vec![]).unwrap();

    assert!(result.is_empty());
}

#[test]
fn context_adapter_evaluates_upstream_once() {
    use std::sync::Mutex;

    let count = Mutex::new(0);
    let matcher = BinaryMatcher::address(TEXT + 8)
        .map_each(|address| {
            *count.lock().unwrap() += 1;
            address
        })
        .with_context()
        .map_each(|(_, address)| address);
    run(&scan_image(), matcher).unwrap();

    assert_eq!(*count.lock().unwrap(), 1);
}

#[test]
fn context_adapter_borrows_non_copy_items_without_requiring_clone() {
    struct Item {
        name: String,
    }
    let matcher = Matcher::<Vec<Item>, Vec<Item>>::identity()
        .with_context()
        .filter_each(|(_, item)| !item.name.is_empty())
        .map_each(|item| item.name);
    let input = ["foo", ""].map(|name| Item { name: name.into() }).into();
    let result = run_stage(&scan_image(), matcher, input).unwrap();

    assert_eq!(result, ["foo"]);
}

#[test]
fn context_map_runs_on_empty_input() {
    let matcher = patterns(&[]).with_context().map(|(ctx, addresses)| {
        assert!(!ctx.image().memory.sections().is_empty());
        addresses.len()
    });
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, 0);
}

#[test]
fn context_adapter_filter_modify_stops_at_first_error_after_none() {
    let matcher: Matcher<Vec<u64>, Vec<u64>> =
        Matcher::identity()
            .with_context()
            .filter_modify(|(_, item)| match item {
                1 => Ok(None),
                2 => Err(ResolveError::new_msg("context filter failed")),
                _ => panic!("must stop after error"),
            });
    let error = run_stage(&scan_image(), matcher, vec![1, 2, 3]).unwrap_err();

    assert_eq!(error.to_string(), "context filter failed");
}

#[test]
fn try_map_each_stops_at_the_first_error() {
    let matcher = Matcher::new::<Vec<u64>>().try_map_each(|item| match item {
        1 => Ok(item),
        2 => Err(ResolveError::new_msg("item failed")),
        _ => panic!("must stop after error"),
    });
    let error = run_stage(&scan_image(), matcher, vec![1, 2, 3]).unwrap_err();

    assert_eq!(error.to_string(), "item failed");
}

fn scan_image() -> Image<'static> {
    let mut text = vec![0x90; 256];
    text[8..11].copy_from_slice(&[0xaa, 0xbb, 0xcc]);
    text[24..27].copy_from_slice(&[0xaa, 0xdd, 0xcc]);
    image(text).with_section(section(
        ".data",
        TARGET,
        SectionKind::Data,
        vec![0xaa, 0xbb, 0xcc],
    ))
}

#[test]
fn patterns_accept_owned_and_borrowed_strings_patterns_and_iterators() {
    let signatures = ["AA BB CC"];
    let strings = vec![String::from("AA BB CC")];
    let parsed = vec![Pattern::new("AA BB CC").unwrap()];
    let matchers = [
        BinaryMatcher::patterns(signatures).unwrap(),
        BinaryMatcher::patterns(signatures.as_slice()).unwrap(),
        BinaryMatcher::patterns(signatures.iter()).unwrap(),
        BinaryMatcher::patterns(&strings).unwrap(),
        BinaryMatcher::patterns(strings.iter()).unwrap(),
        BinaryMatcher::patterns(strings).unwrap(),
        BinaryMatcher::patterns(&parsed).unwrap(),
        BinaryMatcher::patterns(parsed.iter()).unwrap(),
        BinaryMatcher::patterns(parsed).unwrap(),
    ];
    for matcher in matchers {
        assert_eq!(run(&scan_image(), matcher).unwrap(), [TEXT + 8, TARGET]);
    }
}

#[test]
fn patterns_parse_borrowed_strings_without_retaining_their_lifetime() {
    let matcher = {
        let strings = vec![
            String::from("AA DD CC"),
            String::from("AA BB CC"),
            String::from("AA DD CC"),
        ];
        BinaryMatcher::patterns(&strings).unwrap()
    };
    assert_eq!(
        run(&scan_image(), matcher).unwrap(),
        [TEXT + 24, TEXT + 8, TARGET, TEXT + 24]
    );
}

#[test]
fn patterns_preserve_markers_in_strings_and_borrowed_parsed_patterns() {
    let parsed = [Pattern::new("AA | DD CC").unwrap()];
    for matcher in [
        BinaryMatcher::patterns(["AA | DD CC"]).unwrap(),
        BinaryMatcher::patterns(&parsed).unwrap(),
        BinaryMatcher::patterns(parsed).unwrap(),
    ] {
        assert_eq!(run(&scan_image(), matcher).unwrap(), [TEXT + 25]);
    }
}

#[test]
fn patterns_convert_inputs_once_at_construction_not_on_each_resolution() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct CountedSignature(Arc<AtomicUsize>);
    impl IntoPattern for CountedSignature {
        fn into_pattern(self) -> Result<Pattern> {
            self.0.fetch_add(1, Ordering::SeqCst);
            "AA DD CC".into_pattern()
        }
    }

    let count = Arc::new(AtomicUsize::new(0));
    let matcher = BinaryMatcher::patterns([CountedSignature(Arc::clone(&count))]).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let image = scan_image();
    eval(&image, move |ctx| {
        Box::pin(async move {
            for _ in 0..2 {
                assert_eq!(matcher.resolve(ctx).await.unwrap(), [TEXT + 24]);
            }
        })
    });
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn patterns_reject_invalid_signatures_at_construction_with_their_index() {
    let error = BinaryMatcher::patterns(["AA BB CC", "not-a-pattern", "AA DD CC"])
        .err()
        .expect("invalid signature must fail before resolution");
    assert!(error.to_string().starts_with("invalid pattern at index 1:"));
    assert!(format!("{error:#}").contains("bad pattern word"));

    let error = BinaryMatcher::patterns([""])
        .err()
        .expect("empty signature must fail");
    assert!(error.to_string().starts_with("invalid pattern at index 0:"));
    assert!(format!("{error:#}").contains("pattern must contain at least one byte"));
}

#[test]
fn flexible_patterns_accept_empty_collections() {
    for matcher in [
        BinaryMatcher::patterns(Vec::<String>::new()).unwrap(),
        BinaryMatcher::patterns(Vec::<Pattern>::new()).unwrap(),
        BinaryMatcher::patterns(std::iter::empty::<&str>()).unwrap(),
    ] {
        assert!(run(&scan_image(), matcher).unwrap().is_empty());
    }
}

#[test]
fn literal_byte_patterns_match() {
    let matcher = BinaryMatcher::pattern(Pattern::from_bytes(vec![0xaa, 0xbb, 0xcc]).unwrap());
    assert_eq!(run(&scan_image(), matcher).unwrap(), [TEXT + 8, TARGET]);
}

#[test]
fn modify_with_chooses_a_different_offset_for_each_match_from_memory() {
    use patternsleuth::MemoryTrait;

    let matcher = patterns(&["AA ?? CC"])
        .with_context()
        .modify_with(|(ctx, address)| {
            let offset = if ctx.image().memory.u8(address + 1)? == 0xbb {
                1
            } else {
                2
            };
            address
                .checked_add(offset)
                .context("conditional offset overflow")
        });
    assert_eq!(
        run(&scan_image(), matcher).unwrap(),
        [TEXT + 9, TEXT + 26, TARGET + 1]
    );
}

#[test]
fn modify_with_preserves_callback_order_duplicates_and_absolute_addresses() {
    use std::sync::{Arc, Mutex};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&seen);
    let matcher = patterns(&["AA DD CC", "AA BB CC", "AA DD CC"]).modify_with(move |address| {
        captured.lock().unwrap().push(address);
        // This is an absolute address, not an offset or a memory read.
        Ok(0)
    });
    assert_eq!(run(&scan_image(), matcher).unwrap(), [0, 0, 0, 0]);
    assert_eq!(
        *seen.lock().unwrap(),
        [TEXT + 24, TEXT + 8, TARGET, TEXT + 24]
    );
}

#[test]
fn modify_with_skips_callback_on_empty_input_or_inner_error() {
    let empty = patterns(&[]).modify_with(|_| panic!("empty input must skip callback"));
    assert!(run(&scan_image(), empty).unwrap().is_empty());
    let failed = BinaryMatcher::address(0)
        .offset(-1)
        .modify_with(|_| panic!("inner error must skip callback"));
    let error = run(&scan_image(), failed).unwrap_err();
    assert!(error.to_string().contains("address offset overflow"));
}

#[test]
fn modify_with_stops_at_first_callback_error() {
    use std::sync::{Arc, Mutex};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&seen);
    let matcher = patterns(&["AA ?? CC"]).modify_with(move |address| {
        captured.lock().unwrap().push(address);
        if address == TEXT + 24 {
            bail_out!("unsupported instruction");
        }
        Ok(address)
    });
    assert_eq!(
        run(&scan_image(), matcher).unwrap_err().to_string(),
        "unsupported instruction"
    );
    assert_eq!(*seen.lock().unwrap(), [TEXT + 8, TEXT + 24]);
}

#[test]
fn modify_with_propagates_memory_and_checked_arithmetic_errors() {
    use patternsleuth::MemoryTrait;

    let unmapped = BinaryMatcher::address(0)
        .with_context()
        .modify_with(|(ctx, address)| Ok(u64::from(ctx.image().memory.u8(address)?)));
    let error = run(&scan_image(), unmapped).unwrap_err();
    assert_eq!(
        error,
        ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
    );
    let overflow = BinaryMatcher::address(u64::MAX).modify_with(|address| {
        address
            .checked_add(1)
            .context("conditional offset overflow")
    });
    assert_eq!(
        run(&scan_image(), overflow).unwrap_err().to_string(),
        "conditional offset overflow"
    );
}

#[test]
fn filter_preserves_order_duplicates_and_passes_image_context() {
    use std::sync::{Arc, Mutex};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&seen);
    let expected = vec![TEXT + 24, TEXT + 8, TARGET, TEXT + 24];
    let keep = [TEXT + 24, TARGET];
    let matcher = patterns(&["AA DD CC", "AA BB CC", "AA DD CC"])
        .with_context()
        .filter(move |(ctx, address)| {
            assert!(!ctx.image().memory.sections().is_empty());
            captured.lock().unwrap().push(address);
            keep.contains(&address)
        });
    assert_eq!(
        run(&scan_image(), matcher).unwrap(),
        [TEXT + 24, TARGET, TEXT + 24]
    );
    assert_eq!(*seen.lock().unwrap(), expected);
}

#[test]
fn filter_handles_all_none_empty_and_inner_errors() {
    for keep in [false, true] {
        let matcher = patterns(&["AA ?? CC"]).filter(move |_| keep);
        let expected = if keep {
            vec![TEXT + 8, TEXT + 24, TARGET]
        } else {
            vec![]
        };
        assert_eq!(run(&scan_image(), matcher).unwrap(), expected);
    }
    let empty = patterns(&[]).filter(|_| panic!("empty input must skip callback"));
    assert!(run(&scan_image(), empty).unwrap().is_empty());
    let failed = BinaryMatcher::address(0)
        .offset(-1)
        .filter(|_| panic!("inner error must skip callback"));
    assert!(
        run(&scan_image(), failed)
            .unwrap_err()
            .to_string()
            .contains("address offset overflow")
    );
}

#[test]
fn filter_modify_preserves_callback_order_duplicates_and_absolute_addresses() {
    use patternsleuth::MemoryTrait;
    use std::sync::{Arc, Mutex};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&seen);
    let matcher = patterns(&["AA DD CC", "AA BB CC", "AA DD CC"])
        .with_context()
        .filter_modify(move |(ctx, address)| {
            captured.lock().unwrap().push(address);
            Ok((ctx.image().memory.u8(address + 1)? == 0xdd).then_some(0))
        });
    assert_eq!(run(&scan_image(), matcher).unwrap(), [0, 0]);
    assert_eq!(
        *seen.lock().unwrap(),
        [TEXT + 24, TEXT + 8, TARGET, TEXT + 24]
    );
}

#[test]
fn filter_modify_handles_all_none_empty_and_inner_errors() {
    let identity = patterns(&["AA ?? CC"]).filter_modify(|address| Ok(Some(address)));
    assert_eq!(
        run(&scan_image(), identity).unwrap(),
        [TEXT + 8, TEXT + 24, TARGET]
    );
    let none = patterns(&["AA ?? CC"]).filter_modify(|_| Ok(None::<u64>));
    assert!(run(&scan_image(), none).unwrap().is_empty());
    let empty = patterns(&[]).filter_modify::<u64, _>(|_| panic!("empty input must skip callback"));
    assert!(run(&scan_image(), empty).unwrap().is_empty());
    let failed = BinaryMatcher::address(0)
        .offset(-1)
        .filter_modify::<u64, _>(|_| panic!("inner error must skip callback"));
    assert!(
        run(&scan_image(), failed)
            .unwrap_err()
            .to_string()
            .contains("address offset overflow")
    );
}

#[test]
fn filter_modify_stops_at_first_error_after_dropped_results() {
    use std::sync::{Arc, Mutex};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&seen);
    let matcher = patterns(&["AA ?? CC"]).filter_modify(move |address| {
        captured.lock().unwrap().push(address);
        if address == TEXT + 24 {
            bail_out!("filter modification failed");
        }
        Ok(None::<u64>)
    });
    assert_eq!(
        run(&scan_image(), matcher).unwrap_err().to_string(),
        "filter modification failed"
    );
    assert_eq!(*seen.lock().unwrap(), [TEXT + 8, TEXT + 24]);
}

#[test]
fn context_filter_modify_propagates_memory_errors() {
    use patternsleuth::MemoryTrait;

    let matcher = BinaryMatcher::address(0)
        .with_context()
        .filter_modify(|(ctx, address)| Ok(Some(u64::from(ctx.image().memory.u8(address)?))));
    assert_eq!(
        run(&scan_image(), matcher).unwrap_err(),
        ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
    );
}

#[test]
fn address_preserves_full_width_and_does_not_require_mapped_memory() {
    let image = image(vec![]);
    for address in [0, TEXT, u64::MAX] {
        assert_eq!(
            run(&image, BinaryMatcher::address(address)).unwrap(),
            [address]
        );
    }
}

#[test]
fn patterns_scan_all_sections_with_wildcards() {
    assert_eq!(
        run(&scan_image(), patterns(&["AA ?? CC"])).unwrap(),
        [TEXT + 8, TEXT + 24, TARGET]
    );
}

#[test]
fn patterns_preserve_pattern_order_and_duplicates() {
    assert_eq!(
        run(
            &scan_image(),
            patterns(&["AA DD CC", "AA BB CC", "AA DD CC"])
        )
        .unwrap(),
        [TEXT + 24, TEXT + 8, TARGET, TEXT + 24]
    );
}

#[test]
fn empty_and_unmatched_patterns_return_empty() {
    for matcher in [patterns(&[]), patterns(&["DE AD BE EF"])] {
        assert!(run(&scan_image(), matcher).unwrap().is_empty());
    }
}

#[test]
fn first_and_last_follow_result_order_not_address_order() {
    let first = patterns(&["AA DD CC", "AA BB CC"]).first();
    let last = patterns(&["AA BB CC", "AA DD CC"]).last();
    assert_eq!(run(&scan_image(), first).unwrap(), [TEXT + 24]);
    assert_eq!(run(&scan_image(), last).unwrap(), [TEXT + 24]);
}

#[test]
fn selectors_accept_empty_and_singleton_inputs() {
    for wrap in [BinaryMatcher::first, BinaryMatcher::last] {
        assert!(run(&scan_image(), wrap(patterns(&[]))).unwrap().is_empty());
        assert_eq!(
            run(&scan_image(), wrap(BinaryMatcher::address(TEXT))).unwrap(),
            [TEXT]
        );
    }
}

#[test]
fn offsets_apply_to_every_match_and_compose() {
    let matcher = patterns(&["AA ?? CC"]).offset(7).offset(-3);
    assert_eq!(
        run(&scan_image(), matcher).unwrap(),
        [TEXT + 12, TEXT + 28, TARGET + 4]
    );
    assert_eq!(
        run(&scan_image(), BinaryMatcher::address(0).offset(0)).unwrap(),
        [0]
    );
    assert!(
        run(&scan_image(), patterns(&[]).offset(-1))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn offsets_check_unsigned_bounds_including_minimum_signed_offset() {
    let image = image(vec![]);
    for (address, displacement, expected) in [
        (u64::MAX - 1, 1, u64::MAX),
        (1, -1, 0),
        (1u64 << 63, i64::MIN, 0),
    ] {
        assert_eq!(
            run(&image, BinaryMatcher::address(address).offset(displacement)).unwrap(),
            [expected]
        );
    }
    for (address, displacement) in [(u64::MAX, 1), (0, -1), (0, i64::MIN)] {
        let error = run(&image, BinaryMatcher::address(address).offset(displacement)).unwrap_err();
        assert!(error.to_string().contains("address offset overflow"));
    }
}

#[test]
fn sub_receives_results_and_context_then_evaluates_returned_matcher() {
    let matcher = patterns(&["AA DD CC"])
        .with_context()
        .sub(|(ctx, results)| {
            assert_eq!(results, [TEXT + 24]);
            assert_eq!(ctx.image().base_address, BASE);
            Ok(patterns(&["AA BB CC"]).first())
        });
    assert_eq!(run(&scan_image(), matcher).unwrap(), [TEXT + 8]);
}

#[test]
fn sub_runs_on_empty_input_and_can_return_another_sub() {
    let matcher = patterns(&[]).sub(|results| {
        assert!(results.is_empty());
        Ok(BinaryMatcher::address(42)
            .sub(|results| Ok(BinaryMatcher::address(results[0]).offset(-2))))
    });
    assert_eq!(run(&scan_image(), matcher).unwrap(), [40]);
}

#[test]
fn sub_propagates_callback_and_returned_matcher_errors() {
    let callback_error =
        BinaryMatcher::address(1).sub(|_| Err(ResolveError::new_msg("callback failed")));
    assert_eq!(
        run(&scan_image(), callback_error).unwrap_err().to_string(),
        "callback failed"
    );
    let returned_error = patterns(&[]).sub(|_| Ok(BinaryMatcher::address(0).offset(-1)));
    assert!(run(&scan_image(), returned_error).is_err());
}

#[test]
fn all_wrappers_propagate_inner_errors() {
    let wrappers: [for<'a> fn(BinaryMatcher<'a>) -> BinaryMatcher<'a>; 3] = [
        |matcher| matcher.first(),
        |matcher| matcher.last(),
        |matcher| matcher.xrefs().addresses(),
    ];
    for wrap in wrappers {
        assert!(run(&scan_image(), wrap(BinaryMatcher::address(0).offset(-1))).is_err());
    }
    assert!(
        run(
            &scan_image(),
            BinaryMatcher::address(0).offset(-1).offset(1)
        )
        .is_err()
    );
    let matcher = BinaryMatcher::address(0)
        .offset(-1)
        .sub(|_| panic!("callback must not run after an inner error"));
    assert!(run(&scan_image(), matcher).is_err());
}

fn relative(text: &mut [u8], at: usize, opcode: &[u8], target: u64) {
    text[at..at + opcode.len()].copy_from_slice(opcode);
    let next = TEXT + (at + opcode.len() + 4) as u64;
    let displacement = i32::try_from(i128::from(target) - i128::from(next)).unwrap();
    text[at + opcode.len()..at + opcode.len() + 4].copy_from_slice(&displacement.to_le_bytes());
}

fn xrefs<'scope>(target: u64) -> BinaryMatcher<'scope> {
    BinaryMatcher::address(target).xrefs().addresses()
}

#[test]
fn references_return_instruction_sites() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x0d], TARGET);
    relative(&mut text, 72, &[0xe8], TARGET);
    let image = image(text);

    assert_eq!(
        run(&image, BinaryMatcher::address(TARGET).references()).unwrap(),
        [TEXT + 8]
    );
}

#[test]
fn callers_return_call_and_jump_sites() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x0d], TARGET);
    relative(&mut text, 72, &[0xe8], TARGET);
    relative(&mut text, 88, &[0xe9], TARGET);
    relative(&mut text, 144, &[0xe8], TARGET);
    let image = image(text);

    assert_eq!(
        run(&image, BinaryMatcher::address(TARGET).callers()).unwrap(),
        [TEXT + 72, TEXT + 144, TEXT + 88]
    );
}

#[test]
fn references_and_callers_retain_indirect_pointer_scan_behavior() {
    let pointer = BASE + 0x5000;
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x0d], pointer);
    relative(&mut text, 72, &[0xe8], pointer);
    let image = image(text).with_section(section(
        ".data",
        pointer,
        SectionKind::Data,
        TARGET.to_le_bytes().to_vec(),
    ));
    assert_eq!(
        run(&image, BinaryMatcher::address(TARGET).references()).unwrap(),
        [TEXT + 8]
    );
    assert_eq!(
        run(&image, BinaryMatcher::address(TARGET).callers()).unwrap(),
        [TEXT + 72]
    );
}

#[test]
fn function_entries_retain_bounds_size_and_backend_metadata() {
    let image = scan_image();
    let matcher = BinaryMatcher::address(TEXT + 24).then(stages::root_functions());
    let functions = run_stage(&image, matcher, ()).unwrap();
    let metadata = image.get_root_function(TEXT).unwrap().unwrap();

    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].start, TEXT);
    assert_eq!(functions[0].end, TEXT + 0x40);
    assert_eq!(functions[0].size(), 0x40);
    assert_eq!(functions[0].address(), TEXT);
    assert_eq!(
        functions[0].unwind,
        (metadata.unwind != 0).then_some(metadata.unwind)
    );
}

#[test]
fn typed_nodes_convert_to_addresses_without_reordering_or_deduplicating() {
    let matcher = Matcher::from_sync(|()| Ok(vec![Address(2), Address(1), Address(2)])).addresses();
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, [2, 1, 2]);
}

#[test]
fn root_functions_maps_entries_and_interiors_preserving_order_and_duplicates() {
    let matcher = patterns(&["AA DD CC", "AA BB CC", "AA DD CC"]).root_functions();
    assert_eq!(run(&scan_image(), matcher).unwrap(), [TEXT, TEXT, TEXT]);
    for address in [TEXT, TEXT + 8, TEXT + 63, TEXT + 64] {
        assert_eq!(
            run(
                &scan_image(),
                BinaryMatcher::address(address).root_functions()
            )
            .unwrap(),
            [if address < TEXT + 64 { TEXT } else { TEXT + 64 }]
        );
    }
}

#[test]
fn callees_and_call_sites_use_the_containing_function_entry() {
    let image = call_graph();
    for address in [SHARED_CALLER, SHARED_CALLER + 8, SHARED_CALLER + 0x30] {
        assert_eq!(
            run(&image, BinaryMatcher::address(address).callees()).unwrap(),
            [READER_A, READER_B]
        );
        assert_eq!(
            run(&image, BinaryMatcher::address(address).call_sites()).unwrap(),
            [SHARED_CALLER + 8, SHARED_CALLER + 0x18]
        );
    }
    // ENTRY also tail-jumps to OTHER_CALLER; it is not a direct call.
    assert_eq!(
        run(&image, BinaryMatcher::address(ENTRY).callees()).unwrap(),
        [SHARED_CALLER]
    );
}

#[test]
fn callees_preserve_input_order_duplicate_targets_and_recursive_calls() {
    let image = call_graph();
    let mut text = image.memory.sections()[0].data().to_vec();
    relative(&mut text, 0x98, &[0xe8], READER_A);
    relative(&mut text, 0xa8, &[0xe8], SHARED_CALLER);
    let image = image.with_text(text).unwrap();
    let matcher = patterns(&["E8 ?? ?? ?? ??"])
        .filter(|address| [SHARED_CALLER + 8, SHARED_CALLER + 0x18].contains(&address))
        .callees();
    assert_eq!(
        run(&image, matcher).unwrap(),
        [
            READER_A,
            READER_A,
            SHARED_CALLER,
            READER_A,
            READER_A,
            SHARED_CALLER
        ]
    );
}

#[test]
fn outgoing_calls_follow_local_branches_but_not_external_branches_or_dead_code() {
    let mut text = vec![0x90; 256];
    // Visit the taken block before the fallthrough block, but return sites sorted by IP.
    relative(&mut text, 0, &[0x0f, 0x84], TEXT + 0x20);
    relative(&mut text, 8, &[0xe8], TARGET);
    text[13] = 0xc3;
    relative(&mut text, 16, &[0xe8], TARGET + 8); // Unreachable after ret.
    relative(&mut text, 0x20, &[0xe8], TARGET + 16);
    relative(&mut text, 0x28, &[0xe9], TEXT); // Loop, visited only once.
    let image = image(text);
    assert_eq!(
        run(&image, BinaryMatcher::address(TEXT).call_sites()).unwrap(),
        [TEXT + 8, TEXT + 0x20]
    );
    assert_eq!(
        run(&image, BinaryMatcher::address(TEXT).callees()).unwrap(),
        [TARGET, TARGET + 16]
    );
}

#[test]
fn outgoing_calls_exclude_indirect_calls_and_do_not_scan_other_functions() {
    let mut text = vec![0x90; 256];
    text[..2].copy_from_slice(&[0xff, 0xd0]); // call rax: no statically known target.
    relative(&mut text, 8, &[0xe8], TARGET);
    // A conditional branch to an unmapped address must not be followed.
    relative(&mut text, 16, &[0x0f, 0x84], TARGET);
    relative(&mut text, 24, &[0xe9], TEXT + 64);
    relative(&mut text, 72, &[0xe8], TARGET + 8);
    let image = image(text);
    assert_eq!(
        run(&image, BinaryMatcher::address(TEXT).callees()).unwrap(),
        [TARGET]
    );
    assert_eq!(
        run(&image, BinaryMatcher::address(TEXT).call_sites()).unwrap(),
        [TEXT + 8]
    );
}

#[test]
fn outgoing_calls_stop_at_function_boundary_and_indirect_jumps() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0xe8], TARGET);
    relative(&mut text, 72, &[0xe8], TARGET + 8);
    assert_eq!(
        run(&image(text.clone()), BinaryMatcher::address(TEXT).callees()).unwrap(),
        [TARGET]
    );
    text[0..2].copy_from_slice(&[0xff, 0xe0]); // jmp rax.
    assert!(
        run(&image(text), BinaryMatcher::address(TEXT).callees())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn traversal_handles_empty_unknown_and_unreferenced_inputs() {
    let wrappers: [for<'a> fn(BinaryMatcher<'a>) -> BinaryMatcher<'a>; 5] = [
        |matcher: BinaryMatcher| matcher.references().addresses(),
        |matcher: BinaryMatcher| matcher.callers().addresses(),
        |matcher: BinaryMatcher| matcher.root_functions().addresses(),
        |matcher: BinaryMatcher| matcher.callees().addresses(),
        |matcher: BinaryMatcher| matcher.call_sites().addresses(),
    ];
    for wrap in wrappers {
        assert!(run(&scan_image(), wrap(patterns(&[]))).unwrap().is_empty());
        assert!(
            run(&scan_image(), wrap(BinaryMatcher::address(0)))
                .unwrap()
                .is_empty()
        );
        let error = run(&scan_image(), wrap(BinaryMatcher::address(0).offset(-1))).unwrap_err();
        assert!(error.to_string().contains("address offset overflow"));
    }
}

#[test]
fn function_traversal_accepts_an_empty_function_table() {
    let image = construct_image(vec![0x90; 64], 0);
    let wrappers: [for<'a> fn(BinaryMatcher<'a>) -> BinaryMatcher<'a>; 3] = [
        |matcher: BinaryMatcher| matcher.root_functions().addresses(),
        |matcher: BinaryMatcher| matcher.callees().addresses(),
        |matcher: BinaryMatcher| matcher.call_sites().addresses(),
    ];
    for wrap in wrappers {
        assert!(
            run(&image, wrap(BinaryMatcher::address(TEXT)))
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn outgoing_calls_propagate_memory_and_invalid_instruction_errors() {
    let wrappers: [for<'a> fn(BinaryMatcher<'a>) -> BinaryMatcher<'a>; 2] = [
        |matcher: BinaryMatcher| matcher.callees().addresses(),
        |matcher: BinaryMatcher| matcher.call_sites().addresses(),
    ];
    for wrap in wrappers {
        let missing = call_graph().without_section(".text");
        let error = run(&missing, wrap(BinaryMatcher::address(TEXT))).unwrap_err();
        assert_eq!(
            error,
            ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
        );
        let error = run(&image(vec![0x0f]), wrap(BinaryMatcher::address(TEXT))).unwrap_err();
        assert!(error.to_string().contains("invalid instruction"));
    }
}

#[test]
fn xrefs_resolve_lea_calls_and_jumps_to_containing_roots() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x0d], TARGET);
    relative(&mut text, 24, &[0x4c, 0x8d, 0x05], TARGET);
    relative(&mut text, 72, &[0xe8], TARGET);
    relative(&mut text, 88, &[0xe9], TARGET);
    assert_eq!(
        run(&image(text), xrefs(TARGET)).unwrap(),
        [TEXT, TEXT, TEXT + 64, TEXT + 64]
    );
}

#[test]
fn xrefs_find_indirect_pointer_references() {
    let pointer = BASE + 0x5000;
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x0d], pointer);
    relative(&mut text, 72, &[0xe8], pointer);
    let image = image(text).with_section(section(
        ".data",
        pointer,
        SectionKind::Data,
        TARGET.to_le_bytes().to_vec(),
    ));
    assert_eq!(run(&image, xrefs(TARGET)).unwrap(), [TEXT, TEXT + 64]);
}

#[test]
fn xrefs_find_immediate_32_bit_addresses() {
    let mut text = vec![0x90; 256];
    text[8] = 0xb9;
    text[9..13].copy_from_slice(&0x12345678u32.to_le_bytes());
    assert_eq!(run(&image(text), xrefs(0x12345678)).unwrap(), [TEXT]);
}

#[test]
fn xrefs_ignore_references_outside_known_functions() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 144, &[0xe8], TARGET);
    assert!(run(&image(text), xrefs(TARGET)).unwrap().is_empty());
}

#[test]
fn xrefs_accept_empty_and_unreferenced_targets() {
    let image = image(vec![0x90; 256]);
    assert!(run(&image, xrefs(TARGET)).unwrap().is_empty());
    assert!(run(&image, patterns(&[]).xrefs()).unwrap().is_empty());
}

const READER_A: u64 = TEXT;
const READER_B: u64 = TEXT + 0x40;
const SHARED_CALLER: u64 = TEXT + 0x80;
const OTHER_CALLER: u64 = TEXT + 0xc0;
const ENTRY: u64 = TEXT + 0x100;
// Graph (arrows mean "calls", except ENTRY's tail jump to OTHER_CALLER):
// ENTRY -> SHARED_CALLER -> READER_A
//       -> OTHER_CALLER  -> READER_A
//          SHARED_CALLER -> READER_B
fn call_graph() -> Image<'static> {
    let mut text = vec![0x90; 0x140];
    for end in (0x3f..0x140).step_by(0x40) {
        text[end] = 0xc3;
    }
    relative(&mut text, 0x88, &[0xe8], READER_A);
    relative(&mut text, 0x98, &[0xe8], READER_B);
    relative(&mut text, 0xc8, &[0xe8], READER_A);
    relative(&mut text, 0x108, &[0xe8], SHARED_CALLER);
    relative(&mut text, 0x118, &[0xe9], OTHER_CALLER);

    construct_image(text, 5)
}
