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

fn run<T: HasAddress + Send, C: Cardinality>(
    image: &Image<'_>,
    matcher: Matcher<'_, (), T, C>,
) -> Result<Vec<u64>> {
    eval(image, move |ctx| {
        Box::pin(async move { matcher.into_variable().addresses().resolve(ctx).await })
    })
}

fn patterns<'scope>(values: &[&str]) -> BinaryMatcher<'scope> {
    BinaryMatcher::patterns(values).unwrap()
}

fn run_stage<'scope, I, O, C: Cardinality>(
    image: &Image<'_>,
    matcher: Matcher<'scope, I, O, C>,
    input: I,
) -> Result<C::Output<O>>
where
    I: Send + Sync,
    O: Send + Sync,
    C::Output<O>: Sync,
{
    eval(image, move |ctx| {
        Box::pin(async move { matcher.run(input, ctx).await })
    })
}

#[test]
fn address_reads_rip4_preserves_order_duplicates_and_signed_offsets() {
    let bytes = [16_i32, -8, 0]
        .into_iter()
        .flat_map(i32::to_le_bytes)
        .collect();
    let image = image(bytes);
    let matcher = Matcher::from_sync(|()| {
        Ok(vec![
            InstructionSite(TEXT + 4),
            InstructionSite(TEXT),
            InstructionSite(TEXT + 8),
            InstructionSite(TEXT + 4),
        ])
    })
    .rip4();

    assert_eq!(
        run(&image, matcher).unwrap(),
        [TEXT, TEXT + 20, TEXT + 12, TEXT]
    );
}

#[test]
fn address_reads_u64_preserves_order_duplicates_and_full_width() {
    let values = [0xfedc_ba98_7654_3210_u64, 0x0123_4567_89ab_cdef];
    let mut bytes = vec![0xff];
    bytes.extend(values.into_iter().flat_map(u64::to_le_bytes));
    let image = image(bytes);
    let matcher = Matcher::from_sync(|()| {
        Ok(vec![
            Address(TEXT + 9),
            Address(TEXT + 1),
            Address(TEXT + 9),
        ])
    })
    .read_u64();

    assert_eq!(
        run(&image, matcher).unwrap(),
        [values[1], values[0], values[1]]
    );
}

#[test]
fn address_reads_deref_chains_without_validating_the_final_destination() {
    let image = image(
        [TEXT + 8, TARGET]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect(),
    );
    let matcher = BinaryMatcher::address(TEXT).deref().deref();

    assert_eq!(run(&image, matcher).unwrap(), [TARGET]);
}

#[test]
fn address_reads_propagate_truncated_and_unmapped_memory_errors() {
    let image = image(vec![0; 8]);
    let operations: [for<'a> fn(BinaryMatcher<'a>) -> BinaryMatcher<'a>; 3] = [
        |matcher| matcher.rip4(),
        |matcher| matcher.read_u64(),
        |matcher| matcher.deref(),
    ];
    for operation in operations {
        for address in [TEXT + 7, TEXT + 16] {
            let result = run(&image, operation(BinaryMatcher::address(address)));

            assert_eq!(
                result.unwrap_err(),
                ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
            );
        }
    }
}

#[test]
fn address_reads_reject_read_range_overflow_before_accessing_memory() {
    let image = image(vec![]);
    let operations: [for<'a> fn(BinaryMatcher<'a>) -> BinaryMatcher<'a>; 3] = [
        |matcher| matcher.rip4(),
        |matcher| matcher.read_u64(),
        |matcher| matcher.deref(),
    ];
    for operation in operations {
        let error = run(&image, operation(BinaryMatcher::address(u64::MAX))).unwrap_err();

        assert!(error.to_string().contains("overflow"));
    }
}

#[test]
fn address_reads_rip4_rejects_target_overflow_and_underflow() {
    for (address, displacement) in [(0, -8_i32), (u64::MAX - 8, 8)] {
        let image = image(vec![]).with_section(section(
            ".relative",
            address,
            SectionKind::Data,
            displacement.to_le_bytes().to_vec(),
        ));
        let error = run(&image, BinaryMatcher::address(address).rip4()).unwrap_err();

        assert!(error.to_string().contains("target overflow"));
    }
}

#[test]
fn address_reads_accept_empty_input() {
    let matcher = Matcher::from_sync(|()| Ok(Vec::<u64>::new()))
        .rip4()
        .read_u64()
        .deref();
    let result = run(&image(vec![]), matcher).unwrap();

    assert!(result.is_empty());
}

#[test]
fn matchers_compose_directly_with_native_resolver_results() {
    fn build<'scope>() -> patternsleuth::resolvers::Result<Matcher<'scope, (), u64, ExactlyOne>> {
        Ok(BinaryMatcher::patterns(["AA DD CC", "AA DD CC"])?.ensure_one())
    }
    let result: patternsleuth::resolvers::Result<u64> =
        run_stage(&scan_image(), build().unwrap(), ());
    assert_eq!(result.unwrap(), TEXT + 24);

    let ambiguous = BinaryMatcher::patterns(["AA BB CC"]).unwrap().ensure_one();
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
        .try_transform_all(reject)
        .first()
        .xrefs()
        .addresses()
        .with_context()
        .transform_all(|_| -> Vec<u64> { panic!("native error must skip subsequent callbacks") });
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
        .transform(|input| input.addresses)
        .transform(|addresses| addresses.len());
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
        Matcher::from_value(|value: &str| Ok(value.strip_prefix(prefix.as_str()).unwrap_or(value)));
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
        .transform(|_| panic!("callback must not run after an error"));
    assert_eq!(
        run_stage(&scan_image(), matcher, ()).unwrap_err(),
        ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
    );
}

#[test]
fn stages_accept_borrowed_inputs_outputs_and_captures() {
    let text = String::from("prefix:payload");
    let prefix = String::from("prefix:");
    let stage =
        Matcher::new::<&str>().transform(|value| value.strip_prefix(prefix.as_str()).unwrap());
    let result = run_stage(&scan_image(), stage, text.as_str()).unwrap();
    assert_eq!(result, "payload");
    assert_eq!(result.as_ptr(), text[prefix.len()..].as_ptr());
}

#[test]
fn borrowed_outputs_survive_a_shorter_evaluation_context() {
    let text = String::from("borrowed result");
    let result = {
        let image = scan_image();
        let matcher = BinaryMatcher::address(TEXT).transform(|_| text.as_str());
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
        Box::pin(async move { Ok(vec![ctx.image().memory.u8(address)?]) })
    });
    let result = run_stage(&scan_image(), matcher, TEXT + 8).unwrap();

    assert_eq!(result, [0xaa]);
}

#[test]
fn fork_passes_the_same_input_to_both_branches() {
    let left = Matcher::new::<u64>().transform(|value| value + 1);
    let right = Matcher::new::<u64>().transform(|value| value * 2);
    let result = run_stage(&scan_image(), left.fork(right), 3).unwrap();

    assert_eq!(result, (4, 6));
}

#[test]
fn fork_skips_right_branch_after_left_error() {
    let left: Matcher<Vec<u64>, u64> =
        Matcher::items::<u64>().try_transform_all(|_| Err(ResolveError::new_msg("left failed")));
    let right: Matcher<Vec<u64>, u64> =
        Matcher::items::<u64>().transform_all(|_| panic!("right must not run after left error"));
    let error = run_stage(&scan_image(), left.fork(right), vec![1]).unwrap_err();

    assert_eq!(error.to_string(), "left failed");
}

#[test]
fn fork_propagates_right_branch_errors() {
    let left: Matcher<Vec<u64>, u64> = Matcher::identity();
    let right: Matcher<Vec<u64>, u64> =
        Matcher::items::<u64>().try_transform_all(|_| Err(ResolveError::new_msg("right failed")));
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
fn map_accepts_owned_items() {
    let matcher = Matcher::items::<String>().map(|word| word.to_uppercase());
    let result = run_stage(&scan_image(), matcher, vec!["foo".into()]).unwrap();

    assert_eq!(result, ["FOO"]);
}

#[test]
fn map_receives_one_item_and_preserves_order_and_duplicates() {
    let matcher = Matcher::items::<u64>().map(|address| address + 1);
    let result = run_stage(&scan_image(), matcher, vec![3, 1, 3]).unwrap();

    assert_eq!(result, [4, 2, 4]);
}

#[test]
fn candidates_accept_arrays_slices_and_vectors() {
    let addresses = [u64::MAX, 0, u64::MAX];
    let vector = addresses.to_vec();
    let matchers = [
        BinaryMatcher::candidates(addresses),
        BinaryMatcher::candidates(addresses.as_slice()),
        BinaryMatcher::candidates(vector),
    ];
    for matcher in matchers {
        let result = run(&image(vec![]), matcher).unwrap();

        assert_eq!(result, addresses);
    }
}

#[test]
fn candidates_allow_empty_and_singleton_collections() {
    let empty: BinaryMatcher = BinaryMatcher::candidates([]);
    let singleton: Matcher<(), u64, Variable> = BinaryMatcher::candidates([42]);

    assert!(run(&image(vec![]), empty).unwrap().is_empty());
    assert_eq!(run(&image(vec![]), singleton).unwrap(), [42]);
}

#[test]
fn candidates_copy_inputs_and_can_be_resolved_repeatedly() {
    let mut addresses = vec![3_u64, 1, 3];
    let matcher = BinaryMatcher::candidates(&addresses);
    addresses.fill(0);
    let first = run(&image(vec![]), matcher.clone()).unwrap();
    let second = run(&image(vec![]), matcher).unwrap();

    assert_eq!(first, [3, 1, 3]);
    assert_eq!(second, first);
}

#[test]
fn candidates_compose_with_flat_map_and_selection() {
    let matcher = BinaryMatcher::candidates([3, 1, 3])
        .flat_map(|address| BinaryMatcher::candidates([address, address + 4]));
    let result = run(&image(vec![]), matcher.clone()).unwrap();
    let selected = run_stage(&image(vec![]), matcher.at_index(-2), ()).unwrap();

    assert_eq!(result, [3, 7, 1, 5, 3, 7]);
    assert_eq!(selected, 3);
}

#[test]
fn map_skips_empty_input() {
    let matcher =
        Matcher::items::<u64>().map(|_| -> u64 { panic!("empty input must skip the callback") });
    let result = run_stage(&scan_image(), matcher, vec![]).unwrap();

    assert!(result.is_empty());
}

#[test]
fn ensure_one_accepts_repeated_equal_values_and_returns_a_scalar() {
    for input in [vec![3_u64], vec![3, 3]] {
        let matcher = Matcher::items::<u64>().ensure_one();
        let result: u64 = run_stage(&scan_image(), matcher, input).unwrap();

        assert_eq!(result, 3);
    }
}

#[test]
fn ensure_one_preserves_native_empty_and_conflicting_value_errors() {
    for input in [vec![], vec![1_u64, 2], vec![1, 2, 3, 4, 5]] {
        let expected = patternsleuth::resolvers::ensure_one(input.clone()).unwrap_err();
        let matcher = Matcher::items::<u64>().ensure_one();
        let error = run_stage(&scan_image(), matcher, input).unwrap_err();

        assert_eq!(error, expected);
    }
}

#[test]
fn ensure_one_propagates_upstream_errors() {
    let matcher = Matcher::from_sync(|()| -> Result<Vec<u64>> {
        Err(ResolveError::new_msg("upstream failed"))
    })
    .ensure_one();
    let error = run_stage(&scan_image(), matcher, ()).unwrap_err();

    assert_eq!(error.to_string(), "upstream failed");
}

#[test]
fn map_after_ensure_one_chains_scalar_outputs() {
    let matcher = BinaryMatcher::address(3)
        .ensure_one()
        .map(|address| address + 1)
        .map(|address| address.to_string())
        .map(|text| text.len());
    let result: usize = eval(&scan_image(), |ctx| Box::pin(matcher.resolve(ctx))).unwrap();

    assert_eq!(result, 1);
}

#[test]
fn single_map_treats_a_vector_as_one_candidate() {
    let matcher = Matcher::from_sync(|()| Ok(vec![vec![1_u64, 2, 3]]))
        .ensure_one()
        .map(|values| values.into_iter().rev().collect::<Vec<_>>())
        .map(|values| values.len());
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, 3);
}

#[test]
fn single_map_accepts_owned_non_clone_values_and_borrowed_captures() {
    #[derive(Debug, PartialEq)]
    struct Candidate(String);
    let prefix = String::from("prefix:");
    let matcher = Matcher::from_sync(|()| Ok(vec![Candidate("payload".into())]))
        .ensure_one()
        .map(|candidate| format!("{prefix}{}", candidate.0));
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, "prefix:payload");
}

#[test]
fn single_context_maps_read_memory_and_return_to_data_only_callbacks() {
    use patternsleuth::MemoryTrait;

    let matcher = BinaryMatcher::address(TEXT + 8)
        .ensure_one()
        .with_context()
        .map(|(ctx, address)| {
            assert_eq!(ctx.image().base_address, BASE);
            address
        })
        .map(|address| address + 1)
        .with_context()
        .try_map(|(ctx, address)| Ok(ctx.image().memory.u8(address)?))
        .try_map(|byte| Ok(u64::from(byte)));
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, 0xbb);
}

#[test]
fn single_maps_skip_callbacks_after_uniqueness_errors() {
    let matcher = Matcher::from_sync(|()| Ok(vec![1_u64, 2]))
        .ensure_one()
        .map(|_| -> u64 { panic!("uniqueness error must skip map") })
        .with_context()
        .try_map(|_| -> Result<u64> { panic!("uniqueness error must skip try_map") });
    let error = run_stage(&scan_image(), matcher, ()).unwrap_err();

    assert_eq!(
        error,
        patternsleuth::resolvers::ensure_one([1_u64, 2]).unwrap_err()
    );
}

#[test]
fn single_try_map_preserves_native_errors_and_skips_later_callbacks() {
    let matcher = BinaryMatcher::address(TEXT)
        .ensure_one()
        .try_map(|_| -> Result<u64> {
            Err(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError.into())
        })
        .map(|_| -> u64 { panic!("mapping error must skip later callbacks") });
    let error = run_stage(&scan_image(), matcher, ()).unwrap_err();

    assert_eq!(
        error,
        ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
    );
}

#[test]
fn single_matchers_compose_with_scalar_input_stages() {
    let matcher = BinaryMatcher::address(3)
        .ensure_one()
        .map(|value| value + 1)
        .then(Matcher::from_sync(|value| Ok(vec![value, value])));
    let result = run(&scan_image(), matcher).unwrap();

    assert_eq!(result, [4, 4]);
}

#[test]
fn context_map_can_read_image_memory() {
    use patternsleuth::MemoryTrait;

    let matcher = BinaryMatcher::address(TEXT + 8)
        .with_context()
        .try_map(|(ctx, address)| Ok(ctx.image().memory.u8(address)?));
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, [0xaa]);
}

#[test]
fn context_combinators_use_each_runs_image_instead_of_capturing_one() {
    use patternsleuth::MemoryTrait;

    let matcher = BinaryMatcher::address(TEXT + 8)
        .with_context()
        .try_map(|(ctx, address)| Ok(ctx.image().memory.u8(address)?));
    let first = scan_image();
    let second = scan_image();
    let mut text = second.memory.sections()[0].data().to_vec();
    text[8] = 0xbb;
    let second = second.with_text(text).unwrap();
    assert_eq!(run_stage(&first, matcher.clone(), ()).unwrap(), [0xaa]);
    assert_eq!(run_stage(&second, matcher, ()).unwrap(), [0xbb]);
}

#[test]
fn context_map_skips_empty_input() {
    let stage: Matcher<Vec<u64>, u64> = Matcher::identity()
        .with_context()
        .try_map(|_| panic!("empty input must skip the callback"));
    let result = run_stage(&scan_image(), stage, vec![]).unwrap();

    assert!(result.is_empty());
}

#[test]
fn context_adapter_evaluates_upstream_once() {
    use std::sync::Mutex;

    let count = Mutex::new(0);
    let matcher = BinaryMatcher::address(TEXT + 8)
        .map(|address| {
            *count.lock().unwrap() += 1;
            address
        })
        .with_context()
        .map(|(_, address)| address);
    run(&scan_image(), matcher).unwrap();

    assert_eq!(*count.lock().unwrap(), 1);
}

#[test]
fn context_adapter_borrows_non_copy_items_without_requiring_clone() {
    struct Item {
        name: String,
    }
    let matcher = Matcher::<Vec<Item>, Item>::identity()
        .with_context()
        .filter_each(|(_, item)| !item.name.is_empty())
        .map(|item| item.name);
    let input = ["foo", ""].map(|name| Item { name: name.into() }).into();
    let result = run_stage(&scan_image(), matcher, input).unwrap();

    assert_eq!(result, ["foo"]);
}

#[test]
fn context_transform_runs_on_empty_input() {
    let matcher = patterns(&[]).with_context().transform(|(ctx, addresses)| {
        assert!(!ctx.image().memory.sections().is_empty());
        addresses.len()
    });
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, 0);
}

#[test]
fn context_adapter_filter_modify_stops_at_first_error_after_none() {
    let matcher: Matcher<Vec<u64>, u64> =
        Matcher::items::<u64>()
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
fn try_map_stops_at_the_first_error() {
    let matcher = Matcher::items::<u64>().try_map(|item| match item {
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
    assert!(format!("{error:#}").contains("pattern must match at least one byte"));
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
fn selectors_reject_empty_and_accept_singleton_inputs() {
    for wrap in [BinaryMatcher::first, BinaryMatcher::last] {
        assert!(run(&scan_image(), wrap(patterns(&[]))).is_err());
        assert_eq!(
            run(&scan_image(), wrap(BinaryMatcher::address(TEXT))).unwrap(),
            [TEXT]
        );
    }
}

#[test]
fn at_index_selects_from_both_ends_and_returns_a_scalar() {
    for (index, expected) in [(0, 10), (1, 20), (2, 30), (-1, 30), (-2, 20), (-3, 10)] {
        let matcher: Matcher<Vec<u64>, u64, ExactlyOne> = Matcher::items().at_index(index);
        let result: u64 = run_stage(&scan_image(), matcher, vec![10, 20, 30]).unwrap();

        assert_eq!(result, expected);
    }
}

#[test]
fn at_index_rejects_empty_out_of_range_and_extreme_indices() {
    for input in [vec![], vec![10_u64, 20, 30]] {
        let indices = if input.is_empty() {
            vec![0, -1]
        } else {
            vec![3, -4]
        };
        for index in indices.into_iter().chain([isize::MIN, isize::MAX]) {
            let matcher = Matcher::items::<u64>().at_index(index);
            let error = run_stage(&scan_image(), matcher, input.clone()).unwrap_err();

            assert!(error.to_string().contains("out of range"));
        }
    }
}

#[test]
fn first_and_last_match_at_index_values_and_errors() {
    for input in [vec![], vec![10_u64], vec![10, 20, 30]] {
        let first = run_stage(
            &scan_image(),
            Matcher::items::<u64>().first(),
            input.clone(),
        );
        let last = run_stage(&scan_image(), Matcher::items::<u64>().last(), input.clone());
        let at_start = run_stage(
            &scan_image(),
            Matcher::items::<u64>().at_index(0),
            input.clone(),
        );
        let at_end = run_stage(&scan_image(), Matcher::items::<u64>().at_index(-1), input);

        assert_eq!(first, at_start);
        assert_eq!(last, at_end);
    }
}

#[test]
fn at_index_moves_non_clone_candidates() {
    struct Candidate(String);
    let matcher = Matcher::items::<Candidate>()
        .at_index(-2)
        .map(|candidate| candidate.0);
    let input = ["first", "second", "third"]
        .map(|text| Candidate(text.into()))
        .into();
    let result = run_stage(&scan_image(), matcher, input).unwrap();

    assert_eq!(result, "second");
}

#[test]
fn at_index_evaluates_upstream_once_and_preserves_its_error() {
    let count = std::sync::atomic::AtomicUsize::new(0);
    let matcher = Matcher::from_sync(|()| -> Result<Vec<u64>> {
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(ResolveError::new_msg("upstream failed"))
    })
    .at_index(isize::MIN);
    let error = run_stage(&scan_image(), matcher, ()).unwrap_err();

    assert_eq!(error.to_string(), "upstream failed");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn cardinality_preserving_operations_work_after_selectors() {
    let matcher: Matcher<(), u64, ExactlyOne> = patterns(&["AA BB CC"])
        .first()
        .offset(1)
        .with_context()
        .map(|(_, address)| address)
        .try_map(Ok)
        .addresses();
    let result: u64 = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, TEXT + 9);
}

#[test]
fn memory_operations_preserve_exactly_one_through_pointer_chains() {
    let mut bytes = vec![0x90; 40];
    relative(&mut bytes, 0, &[0xe8], TEXT + 16);
    bytes[16..24].copy_from_slice(&(TEXT + 24).to_le_bytes());
    bytes[24..32].copy_from_slice(&TARGET.to_le_bytes());
    let image = image(bytes);
    let matcher: Matcher<(), u64, ExactlyOne> = patterns(&["E8 | ?? ?? ?? ??"])
        .ensure_one()
        .rip4()
        .deref()
        .read_u64();
    let result = run_stage(&image, matcher, ()).unwrap();

    assert_eq!(result, TARGET);
}

#[test]
fn filtering_and_expansion_return_variable_cardinality() {
    let filtered: Matcher<(), u64> = BinaryMatcher::address(10).ensure_one().filter(|_| false);
    let expanded: Matcher<(), u64> = BinaryMatcher::address(10)
        .ensure_one()
        .expand(|item| vec![item, item]);
    let contextual: Matcher<(), u64> = BinaryMatcher::address(10)
        .ensure_one()
        .with_context()
        .filter_modify(|_| Ok(None));

    assert!(run_stage(&scan_image(), filtered, ()).unwrap().is_empty());
    assert_eq!(run_stage(&scan_image(), expanded, ()).unwrap(), [10, 10]);
    assert!(run_stage(&scan_image(), contextual, ()).unwrap().is_empty());
}

#[test]
fn flat_map_evaluates_matchers_in_candidate_order_with_duplicates() {
    let matcher = Matcher::items::<u64>()
        .flat_map(|value| Matcher::from_sync(move |()| Ok(vec![value, value + 10])));
    let result = run_stage(&scan_image(), matcher, vec![3, 1, 3]).unwrap();

    assert_eq!(result, [3, 13, 1, 11, 3, 13]);
}

#[test]
fn flat_map_accepts_exactly_one_inner_and_outer_matchers() {
    let matcher: Matcher<(), u64> = BinaryMatcher::address(3)
        .ensure_one()
        .flat_map(|value| BinaryMatcher::address(value).ensure_one().offset(1));
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, [4]);
}

#[test]
fn flat_map_skips_empty_input_and_accepts_empty_inner_results() {
    let empty = Matcher::items::<u64>()
        .flat_map(|_| -> BinaryMatcher { panic!("empty input must skip matcher construction") });
    let no_matches = BinaryMatcher::address(3).flat_map(|_| patterns(&[]));

    assert!(run_stage(&scan_image(), empty, vec![]).unwrap().is_empty());
    assert!(run_stage(&scan_image(), no_matches, ()).unwrap().is_empty());
}

#[test]
fn flat_map_captures_non_clone_candidates_and_borrowed_data() {
    struct Candidate(String);
    let prefix = String::from("prefix:");
    let matcher = Matcher::items::<Candidate>().flat_map(|candidate| {
        let prefix = prefix.as_str();
        Matcher::from_value(move |()| Ok(format!("{prefix}{}", candidate.0)))
    });
    let result = run_stage(&scan_image(), matcher, vec![Candidate("payload".into())]).unwrap();

    assert_eq!(result, ["prefix:payload"]);
}

#[test]
fn flat_map_runs_async_inner_matchers_against_the_current_image() {
    use patternsleuth::MemoryTrait;

    let matcher = Matcher::items::<u64>().flat_map(|address| {
        Matcher::from_async(move |(), ctx| {
            Box::pin(async move { Ok(vec![u64::from(ctx.image().memory.u8(address)?)]) })
        })
    });
    let result = run_stage(&scan_image(), matcher, vec![TEXT + 8, TEXT + 9]).unwrap();

    assert_eq!(result, [0xaa, 0xbb]);
}

#[test]
fn flat_map_retains_nested_function_search_bounds() {
    let inner = BinaryMatcher::address(3)
        .flat_map(|_| BinaryMatcher::address(4).flat_map(|_| patterns(&["AA BB CC"])));
    let matcher = functions(&[(TEXT, TEXT + 16)]).sub(inner);
    let result = run(&scan_image(), matcher).unwrap();

    assert_eq!(result, [TEXT + 8]);
}

#[test]
fn flat_map_can_capture_reference_sites_while_resolving_functions() {
    let matcher = BinaryMatcher::address(TEXT + 24).flat_map(|reference| {
        BinaryMatcher::address(reference)
            .root_functions()
            .map(move |function| (reference, function.start))
    });
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, [(TEXT + 24, TEXT)]);
}

#[test]
fn context_flat_map_passes_context_only_to_matcher_construction() {
    let matcher = BinaryMatcher::address(3)
        .with_context()
        .flat_map(|(ctx, value)| {
            BinaryMatcher::address(ctx.image().base_address + value).ensure_one()
        })
        .map(|address| address + 1);
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, [BASE + 4]);
}

#[test]
fn try_flat_map_stops_after_callback_errors() {
    let matcher = Matcher::items::<u64>().try_flat_map(|value| match value {
        1 => Ok(BinaryMatcher::address(value)),
        2 => Err(ResolveError::new_msg("construction failed")),
        _ => panic!("construction error must skip later candidates"),
    });
    let error = run_stage(&scan_image(), matcher, vec![1, 2, 3]).unwrap_err();

    assert_eq!(error.to_string(), "construction failed");
}

#[test]
fn flat_map_stops_after_inner_errors_without_constructing_later_matchers() {
    let matcher = Matcher::items::<u64>().flat_map(|value| {
        assert_eq!(value, 1);
        Matcher::from_sync(|()| -> Result<Vec<u64>> {
            Err(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError.into())
        })
    });
    let error = run_stage(&scan_image(), matcher, vec![1, 2]).unwrap_err();

    assert_eq!(
        error,
        ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
    );
}

#[test]
fn flat_map_preserves_outer_errors_without_constructing_inner_matchers() {
    let matcher =
        Matcher::from_sync(|()| -> Result<Vec<u64>> { Err(ResolveError::new_msg("outer failed")) })
            .flat_map(|_| -> BinaryMatcher { panic!("outer error must skip the callback") });
    let error = run_stage(&scan_image(), matcher, ()).unwrap_err();

    assert_eq!(error.to_string(), "outer failed");
}

#[test]
fn function_sub_accepts_both_exactly_one_receivers_and_inner_matchers() {
    let matcher: Matcher<(), u64> = BinaryMatcher::address(TEXT)
        .root_functions()
        .ensure_one()
        .sub(patterns(&["AA BB CC"]).first().offset(1));
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, [TEXT + 9]);
}

#[test]
fn set_operations_accept_mixed_cardinalities_and_return_variable() {
    let matcher: Matcher<(), u64> = BinaryMatcher::address(3)
        .ensure_one()
        .union(Matcher::from_sync(|()| Ok(vec![1, 3, 2])))
        .intersect(BinaryMatcher::address(3).ensure_one());
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert_eq!(result, [3]);
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
fn sub_scans_each_function_in_order_preserving_duplicates() {
    let matcher = functions(&[
        (TEXT + 24, TEXT + 28),
        (TEXT + 8, TEXT + 12),
        (TEXT + 24, TEXT + 28),
    ])
    .sub(patterns(&["AA ?? CC"]));

    assert_eq!(
        run(&scan_image(), matcher).unwrap(),
        [TEXT + 24, TEXT + 8, TEXT + 24]
    );
}

#[test]
fn sub_skips_empty_functions_and_empty_ranges() {
    for ranges in [vec![], vec![(TEXT, TEXT)]] {
        let matcher = functions(&ranges).sub(Matcher::from_sync(|()| -> Result<Vec<u64>> {
            panic!("empty scopes must skip the inner matcher")
        }));

        assert!(run(&scan_image(), matcher).unwrap().is_empty());
    }
}

#[test]
fn sub_stops_at_the_first_inner_error() {
    let count = std::sync::atomic::AtomicUsize::new(0);
    let inner = Matcher::from_sync(|()| -> Result<Vec<u64>> {
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(ResolveError::new_msg("inner failed"))
    });
    let matcher = functions(&[(TEXT, TEXT + 8), (TEXT + 8, TEXT + 16)]).sub(inner);

    assert_eq!(
        run(&scan_image(), matcher).unwrap_err().to_string(),
        "inner failed"
    );
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1);
}

fn functions<'scope>(ranges: &[(u64, u64)]) -> Matcher<'scope, (), FunctionEntry> {
    let entries = ranges
        .iter()
        .map(|&(start, end)| FunctionEntry {
            start,
            end,
            unwind: None,
        })
        .collect::<Vec<_>>();
    Matcher::from_sync(move |()| Ok(entries.clone()))
}

#[test]
fn sub_requires_the_complete_pattern_to_fit_and_retains_markers() {
    let image = image(vec![0xaa, 0xbb, 0xcc, 0xaa, 0xbb, 0xcc]);
    let matcher = functions(&[(TEXT, TEXT + 5)]).sub(patterns(&["AA | BB CC"]));

    assert_eq!(run(&image, matcher).unwrap(), [TEXT + 1]);
    assert!(
        run(
            &image,
            functions(&[(TEXT + 1, TEXT + 6)]).sub(patterns(&["AA BB CC"]))
        )
        .unwrap()
        .contains(&(TEXT + 3))
    );
}

#[test]
fn sub_nested_scopes_intersect_and_restore_the_parent() {
    let inner = functions(&[(TEXT, TEXT + 64), (TEXT + 64, TEXT + 80)])
        .sub(patterns(&["AA ?? CC"]))
        .union(patterns(&["AA DD CC"]));
    let matcher = functions(&[(TEXT + 8, TEXT + 27)])
        .sub(inner)
        .union(patterns(&["AA BB CC"]));

    assert_eq!(
        run(&scan_image(), matcher).unwrap(),
        [TEXT + 8, TEXT + 24, TARGET]
    );
}

#[test]
fn sub_allows_rip_targets_and_reads_outside_the_function() {
    let mut bytes = vec![0x90; 32];
    relative(&mut bytes, 0, &[0x48, 0x8b, 0x05], TEXT + 16);
    bytes[16..24].copy_from_slice(&TARGET.to_le_bytes());
    let image = image(bytes);
    let matcher =
        functions(&[(TEXT, TEXT + 7)]).sub(patterns(&["48 8B 05 | ?? ?? ?? ??"]).rip4().deref());

    assert_eq!(run(&image, matcher).unwrap(), [TARGET]);
}

#[test]
fn sub_scopes_reference_and_caller_scans() {
    let mut bytes = vec![0x90; 96];
    relative(&mut bytes, 0, &[0x48, 0x8d, 0x05], TARGET);
    relative(&mut bytes, 8, &[0xe8], TARGET);
    relative(&mut bytes, 64, &[0x48, 0x8d, 0x05], TARGET);
    relative(&mut bytes, 72, &[0xe8], TARGET);
    let image = image(bytes);
    let references =
        functions(&[(TEXT, TEXT + 64)]).sub(BinaryMatcher::address(TARGET).references());
    let callers = functions(&[(TEXT, TEXT + 64)]).sub(BinaryMatcher::address(TARGET).callers());

    assert_eq!(run(&image, references).unwrap(), [TEXT]);
    assert_eq!(run(&image, callers).unwrap(), [TEXT + 8]);
}

#[test]
fn sub_rejects_reversed_function_ranges() {
    let matcher = functions(&[(TEXT + 8, TEXT)]).sub(patterns(&["AA"]));

    assert!(
        run(&scan_image(), matcher)
            .unwrap_err()
            .to_string()
            .contains("invalid function range")
    );
}

#[test]
fn sub_accepts_native_function_entries() {
    let matcher = BinaryMatcher::address(TEXT + 24)
        .root_functions()
        .sub(patterns(&["AA BB CC"]));

    assert_eq!(run(&scan_image(), matcher).unwrap(), [TEXT + 8]);
}

#[test]
fn sub_scopes_custom_async_scans_and_context_callbacks() {
    let inner = Matcher::from_async(|(), ctx| {
        Box::pin(async move {
            assert_eq!(ctx.bounds(), Some(TEXT..TEXT + 16));
            Ok(ctx.scan(Pattern::new("AA BB CC").unwrap()).await)
        })
    })
    .with_context()
    .map(|(ctx, address)| {
        assert_eq!(ctx.bounds(), Some(TEXT..TEXT + 16));
        address
    });
    let matcher = functions(&[(TEXT, TEXT + 16)]).sub(inner);

    assert_eq!(run(&scan_image(), matcher).unwrap(), [TEXT + 8]);
}

#[test]
fn sub_limits_traversal_sites_but_not_call_targets() {
    let mut bytes = vec![0x90; 128];
    relative(&mut bytes, 0, &[0x0f, 0x84], TEXT + 32);
    relative(&mut bytes, 8, &[0xe8], TARGET);
    relative(&mut bytes, 16, &[0xe8], TARGET + 8);
    relative(&mut bytes, 32, &[0xe8], TARGET + 16);
    let image = image(bytes);
    let matcher = functions(&[(TEXT, TEXT + 18)]).sub(BinaryMatcher::address(TEXT).callees());

    assert_eq!(run(&image, matcher).unwrap(), [TARGET]);
}

#[test]
fn sub_propagates_outer_errors_without_running_the_inner_matcher() {
    let outer = Matcher::from_sync(|()| -> Result<Vec<FunctionEntry>> {
        Err(ResolveError::new_msg("outer failed"))
    });
    let matcher = outer.sub(Matcher::from_sync(|()| -> Result<Vec<u64>> {
        panic!("outer error must skip the inner matcher")
    }));

    assert_eq!(
        run(&scan_image(), matcher).unwrap_err().to_string(),
        "outer failed"
    );
}

#[test]
fn all_wrappers_propagate_inner_errors() {
    let wrappers: [for<'a> fn(BinaryMatcher<'a>) -> BinaryMatcher<'a>; 3] = [
        |matcher| matcher.first().into_variable(),
        |matcher| matcher.last().into_variable(),
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
        .transform_all(|_| -> Vec<u64> { panic!("callback must not run after an inner error") });
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
fn root_functions_skip_addresses_outside_the_function_table() {
    let matcher = BinaryMatcher::candidates([0, TEXT - 1, TEXT, TEXT + 127, TEXT + 128, u64::MAX])
        .root_functions()
        .addresses();
    let result = run(&scan_image(), matcher).unwrap();

    assert_eq!(result, [TEXT, TEXT + 64]);
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
