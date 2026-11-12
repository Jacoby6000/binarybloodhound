#[test]
fn ensure_non_empty_retains_non_clone_values_duplicates_and_ancestry() {
    struct Source(u64);
    let original = run_nodes(
        &scan_image(),
        Matcher::items::<Source>(),
        vec![Source(7), Source(7)],
    )
    .unwrap();
    let matcher: Matcher<_, _, Variable, _> = Matcher::from_nodes(&original).ensure_non_empty();
    let nodes = run_nodes(&scan_image(), matcher, ()).unwrap();

    assert_eq!(nodes.len(), 2);
    for (node, original) in nodes.iter().zip(&original) {
        assert_eq!(node.value.0, 7);
        assert!(std::sync::Arc::ptr_eq(&node.value, &original.value));
        assert!(std::sync::Arc::ptr_eq(
            &node.parents()[0],
            &original.parents()[0]
        ));
    }
}

#[test]
fn ensure_non_empty_preserves_exactly_one_cardinality() {
    struct Source(u64);
    let matcher: Matcher<_, _, ExactlyOne, _> = Matcher::new::<Source>().ensure_non_empty();
    let node = run_nodes(&scan_image(), matcher, Source(7)).unwrap();

    assert_eq!(node.value.0, 7);
    assert_eq!(node.parent(), &());
}

#[test]
fn ensure_non_empty_rejects_empty_output_before_downstream_transforms() {
    let matcher = BinaryMatcher::candidates([])
        .ensure_non_empty()
        .transform(|_| -> u64 { panic!("empty output must skip downstream callbacks") });
    let error = run_nodes(&scan_image(), matcher, ()).unwrap_err();

    assert_eq!(error.to_string(), "expected at least one value");
}

#[test]
fn ensure_non_empty_preserves_upstream_errors() {
    let matcher = Matcher::from_sync(|()| -> Result<Vec<u64>> {
        Err(ResolveError::new_msg("source failed"))
    })
    .ensure_non_empty();
    let error = run_nodes(&scan_image(), matcher, ()).unwrap_err();

    assert_eq!(error.to_string(), "source failed");
}

#[test]
fn sources_always_start_typed_ancestry() {
    let node: Trace<u64> =
        run_nodes(&scan_image(), BinaryMatcher::address(42).first(), ()).unwrap();

    assert_eq!(*node.value, 42);
    assert_eq!(node.parent(), &());
    assert_eq!(node.parents().len(), 1);
}

#[test]
fn navigation_builds_statically_typed_parent_chains_automatically() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x05], TEXT + 64);
    let matcher = BinaryMatcher::address(TEXT + 64)
        .root_functions()
        .references()
        .root_functions()
        .first();
    let node: Function<Reference<Function<Trace<u64>>>> =
        run_nodes(&image(text), matcher, ()).unwrap();

    assert_eq!(node.value.start, TEXT);
    assert_eq!(node.parent().value.0, TEXT + 8);
    assert_eq!(node.parent().parent().value.start, TEXT + 64);
    assert_eq!(*node.parent().parent().parent().value, TEXT + 64);
}

#[test]
fn references_share_their_parent_without_cloning_values() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x05], TARGET);
    relative(&mut text, 24, &[0x48, 0x8d, 0x05], TARGET);
    let nodes = run_nodes(
        &image(text),
        BinaryMatcher::address(TARGET).references(),
        (),
    )
    .unwrap();

    assert_eq!(nodes.len(), 2);
    assert!(std::sync::Arc::ptr_eq(
        &nodes[0].parents()[0],
        &nodes[1].parents()[0]
    ));
    assert_eq!(*nodes[0].parent().value, TARGET);
}

#[test]
fn navigation_preserves_source_order_and_duplicates() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x05], TARGET);
    relative(&mut text, 72, &[0x48, 0x8d, 0x05], TARGET + 8);
    let matcher = BinaryMatcher::candidates([TARGET + 8, TARGET, TARGET + 8])
        .references()
        .map(|node| (node.value.0, *node.parent().value));
    let result = run_stage(&image(text), matcher, ()).unwrap();

    assert_eq!(
        result,
        [
            (TEXT + 72, TARGET + 8),
            (TEXT + 8, TARGET),
            (TEXT + 72, TARGET + 8)
        ]
    );
}

#[test]
fn selectors_and_filters_retain_the_selected_ancestry() {
    let matcher = BinaryMatcher::candidates([TEXT + 8, TEXT + 72, TEXT + 24])
        .root_functions()
        .filter(|node| node.value.start == TEXT)
        .last();
    let node = run_nodes(&scan_image(), matcher, ()).unwrap();

    assert_eq!(node.value.start, TEXT);
    assert_eq!(*node.parent().value, TEXT + 24);
}

#[test]
fn ensure_one_merges_parents_of_equal_values() {
    let matcher = BinaryMatcher::candidates([TEXT + 8, TEXT + 24])
        .root_functions()
        .ensure_one();
    let node = run_nodes(&scan_image(), matcher, ()).unwrap();

    assert_eq!(node.value.start, TEXT);
    assert_eq!(
        node.parents()
            .iter()
            .map(|parent| *parent.value)
            .collect::<Vec<_>>(),
        [TEXT + 8, TEXT + 24]
    );
}

#[test]
fn ensure_one_retains_native_uniqueness_errors_with_ancestry() {
    for values in [vec![], vec![TEXT, TEXT + 64]] {
        let error = run_nodes(
            &scan_image(),
            BinaryMatcher::candidates(&values).ensure_one(),
            (),
        )
        .unwrap_err();
        let expected = patternsleuth::resolvers::ensure_one(values).unwrap_err();

        assert_eq!(error, expected);
    }
}

#[test]
fn union_merges_all_contributors_and_preserves_first_occurrences() {
    let left = BinaryMatcher::candidates([TEXT + 72, TEXT + 8, TEXT + 24]).root_functions();
    let right = BinaryMatcher::candidates([TEXT + 16, TEXT + 80]).root_functions();
    let nodes = run_nodes(&scan_image(), Matcher::union_all([left, right]), ()).unwrap();

    assert_eq!(
        nodes
            .iter()
            .map(|node| node.value.start)
            .collect::<Vec<_>>(),
        [TEXT + 64, TEXT]
    );
    assert_eq!(
        nodes[0]
            .parents()
            .iter()
            .map(|parent| *parent.value)
            .collect::<Vec<_>>(),
        [TEXT + 72, TEXT + 80]
    );
    assert_eq!(
        nodes[1]
            .parents()
            .iter()
            .map(|parent| *parent.value)
            .collect::<Vec<_>>(),
        [TEXT + 8, TEXT + 24, TEXT + 16]
    );
}

#[test]
fn intersection_retains_contributors_from_every_branch() {
    let branches = [
        vec![TEXT + 8, TEXT + 72],
        vec![TEXT + 16, TEXT + 80],
        vec![TEXT + 24],
    ]
    .map(|addresses| BinaryMatcher::candidates(addresses).root_functions());
    let nodes = run_nodes(&scan_image(), Matcher::intersect_all(branches), ()).unwrap();

    assert_eq!(nodes.len(), 1);
    assert_eq!(
        nodes[0]
            .parents()
            .iter()
            .map(|parent| *parent.value)
            .collect::<Vec<_>>(),
        [TEXT + 8, TEXT + 16, TEXT + 24]
    );
}

#[test]
fn empty_sets_still_return_empty_node_collections() {
    let union = Matcher::<(), u64>::union_all([]);
    let intersection = Matcher::<(), u64>::intersect_all([]);

    assert!(run_nodes(&scan_image(), union, ()).unwrap().is_empty());
    assert!(
        run_nodes(&scan_image(), intersection, ())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn sets_stop_at_the_first_branch_error() {
    let failing = Matcher::from_sync(|()| -> Result<Vec<u64>> {
        Err(ResolveError::new_msg("trace branch failed"))
    });
    let later = Matcher::from_sync(|()| -> Result<Vec<u64>> { panic!("must skip later branches") });
    let error = run_nodes(&scan_image(), failing.union(later), ()).unwrap_err();

    assert_eq!(error.to_string(), "trace branch failed");
}

#[test]
fn intersection_does_not_hide_later_errors_when_empty() {
    let failing = Matcher::from_sync(|()| -> Result<Vec<u64>> {
        Err(ResolveError::new_msg("intersection failed"))
    });
    let error = run_nodes(
        &scan_image(),
        BinaryMatcher::candidates([]).intersect(failing),
        (),
    )
    .unwrap_err();

    assert_eq!(error.to_string(), "intersection failed");
}

#[test]
fn xrefs_retain_intermediate_instructions_and_evaluate_sources_once() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let evaluations = AtomicUsize::new(0);
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x05], TARGET);
    relative(&mut text, 72, &[0xe8], TARGET);
    let matcher = Matcher::from_sync(|()| {
        evaluations.fetch_add(1, Ordering::SeqCst);
        Ok(vec![TARGET])
    })
    .xrefs();
    let nodes = run_nodes(&image(text), matcher, ()).unwrap();

    assert_eq!(evaluations.load(Ordering::SeqCst), 1);
    assert_eq!(
        nodes
            .iter()
            .map(|node| (
                node.value.start,
                node.parent().value.0,
                *node.parent().parent().value
            ))
            .collect::<Vec<_>>(),
        [(TEXT, TEXT + 8, TARGET), (TEXT + 64, TEXT + 72, TARGET)]
    );
}

#[test]
fn callees_keep_call_sites_and_source_functions() {
    let nodes = run_nodes(
        &call_graph(),
        BinaryMatcher::address(SHARED_CALLER)
            .root_functions()
            .callees(),
        (),
    )
    .unwrap();

    assert_eq!(nodes.len(), 2);
    assert_eq!(*nodes[0].value, nodes[0].parent().value.target);
    assert_eq!(
        nodes[0].parent().value.site,
        InstructionSite(SHARED_CALLER + 8)
    );
    assert_eq!(nodes[0].parent().parent().value.start, SHARED_CALLER);
}

#[test]
fn memory_reads_preserve_cardinality_and_each_parent() {
    let mut text = vec![0x90; 256];
    text[8..12].copy_from_slice(&4_i32.to_le_bytes());
    text[16..24].copy_from_slice(&TARGET.to_le_bytes());
    let matcher = BinaryMatcher::address(TEXT + 8).ensure_one().rip4().deref();
    let node = run_nodes(&image(text), matcher, ()).unwrap();

    assert_eq!(*node.value, TARGET);
    assert_eq!(*node.parent().value, TEXT + 16);
    assert_eq!(*node.parent().parent().value, TEXT + 8);
}

#[test]
fn walkers_borrow_root_and_parent_reference_and_retain_both() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x05], TARGET);
    let matcher = BinaryMatcher::address(TARGET)
        .references()
        .root_functions()
        .walk_disassembly(
            |root| (root.value.start, root.parent().value.0),
            |state, _| Ok(Control::Return(state)),
        );
    let nodes = run_nodes(&image(text), matcher, ()).unwrap();

    assert_eq!(*nodes[0].value, (TEXT, TEXT + 8));
    assert_eq!(nodes[0].parent().value.start, TEXT);
    assert_eq!(nodes[0].parent().parent().value.0, TEXT + 8);
}

#[test]
fn sub_retains_both_scoping_function_and_inner_ancestry() {
    let mut text = vec![0x90; 256];
    text[8..11].copy_from_slice(&[0xaa, 0xbb, 0xcc]);
    text[72..75].copy_from_slice(&[0xaa, 0xbb, 0xcc]);
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .sub(patterns(&["AA BB CC"]).offset(1));
    let nodes = run_nodes(&image(text), matcher, ()).unwrap();

    assert_eq!(nodes.len(), 1);
    assert_eq!(*nodes[0].value, TEXT + 9);
    assert_eq!(nodes[0].parent().outer.value.start, TEXT);
    assert_eq!(*nodes[0].parent().inner.value, TEXT + 8);
}

#[test]
fn disassemble_until_retains_function_parent() {
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .ensure_one()
        .disassemble_until(|instruction| instruction.ip() == TEXT + 2);
    let node = run_nodes(&image(vec![0x90; 256]), matcher, ()).unwrap();

    assert_eq!(node.value.len(), 3);
    assert_eq!(node.parent().value.start, TEXT);
}

#[test]
fn repeated_evaluations_build_fresh_ancestry() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let address = AtomicU64::new(TEXT + 8);
    let matcher = Matcher::from_sync(|()| Ok(vec![address.fetch_add(8, Ordering::SeqCst)]))
        .root_functions()
        .ensure_one();
    let first = run_nodes(&scan_image(), matcher.clone(), ()).unwrap();
    let second = run_nodes(&scan_image(), matcher, ()).unwrap();

    assert_eq!(*first.parent().value, TEXT + 8);
    assert_eq!(*second.parent().value, TEXT + 16);
}

#[test]
fn maps_borrow_non_clone_values_and_retain_them() {
    struct Source(String);
    let matcher = Matcher::items::<Source>()
        .map(|node| node.value.0.len())
        .first();
    let node = run_nodes(&scan_image(), matcher, vec![Source("first".into())]).unwrap();

    assert_eq!(*node.value, 5);
    assert_eq!(node.parent().value.0, "first");
}

#[test]
fn parent_values_can_hold_borrowed_data() {
    struct Source<'a> {
        address: u64,
        label: &'a str,
    }
    impl HasAddress for Source<'_> {
        fn address(&self) -> u64 {
            self.address
        }
    }
    let label = String::from("origin");
    let matcher = Matcher::from_sync(|()| {
        Ok(vec![Source {
            address: TEXT + 8,
            label: &label,
        }])
    })
    .root_functions()
    .first();
    let node = run_nodes(&scan_image(), matcher, ()).unwrap();

    assert_eq!(node.value.start, TEXT);
    assert_eq!(node.parent().value.label, "origin");
}

#[test]
fn earlier_merges_remain_visible_through_later_navigation() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 8, &[0x48, 0x8d, 0x05], TEXT + 64);
    let matcher = BinaryMatcher::candidates([TEXT + 72, TEXT + 80])
        .root_functions()
        .ensure_one()
        .references()
        .root_functions()
        .first();
    let node = run_nodes(&image(text), matcher, ()).unwrap();

    assert_eq!(
        node.parent()
            .parent()
            .parents()
            .iter()
            .map(|parent| *parent.value)
            .collect::<Vec<_>>(),
        [TEXT + 72, TEXT + 80]
    );
}

#[test]
fn flat_map_retains_outer_and_inner_derivations_without_cloning_values() {
    struct Source(u64);
    let matcher = Matcher::items::<Source>()
        .flat_map(|node| BinaryMatcher::address(node.value.0).offset(8))
        .first();
    let node: Trace<u64, Composition<Trace<Source>, Trace<u64>>> =
        run_nodes(&scan_image(), matcher, vec![Source(TEXT)]).unwrap();

    assert_eq!(*node.value, TEXT + 8);
    assert_eq!(node.parent().outer.value.0, TEXT);
    assert_eq!(*node.parent().inner.value, TEXT);
}

#[test]
fn then_retains_the_upstream_collection_and_inner_derivation() {
    let next = Matcher::from_sync(|nodes: Vec<Trace<u64>>| Ok(vec![*nodes[0].value + 8]));
    let matcher = BinaryMatcher::address(TEXT).then(next).first();
    let node = run_nodes(&scan_image(), matcher, ()).unwrap();

    assert_eq!(*node.value, TEXT + 8);
    assert_eq!(*node.parent().outer[0].value, TEXT);
}

#[test]
fn transforms_retain_all_contributors() {
    let matcher = Matcher::items::<String>()
        .transform(|nodes| nodes.iter().map(|node| node.value.len()).sum::<usize>());
    let node = run_nodes(&scan_image(), matcher, vec!["ab".into(), "cde".into()]).unwrap();

    assert_eq!(*node.value, 5);
    assert_eq!(node.parent().len(), 2);
}

#[test]
fn context_maps_borrow_and_retain_non_clone_values() {
    struct Source(u64);
    let matcher = Matcher::items::<Source>()
        .with_context()
        .map(|(_, node)| node.value.0 + 1)
        .first();
    let node = run_nodes(&scan_image(), matcher, vec![Source(TEXT)]).unwrap();

    assert_eq!(*node.value, TEXT + 1);
    assert_eq!(node.parent().value.0, TEXT);
}

#[test]
fn heterogeneous_union_keeps_typed_contributors_on_both_sides() {
    let left = BinaryMatcher::address(TEXT).offset(8);
    let right = BinaryMatcher::address(TEXT + 8);
    let nodes = run_nodes(&scan_image(), left.union(right), ()).unwrap();

    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].parents().len(), 2);
    let Contributor::Left(parent) = nodes[0].parents()[0].as_ref() else {
        panic!("left contributor");
    };
    assert_eq!(*parent.value, TEXT);
    assert!(matches!(
        nodes[0].parents()[1].as_ref(),
        Contributor::Right(_)
    ));
}

#[test]
fn heterogeneous_intersection_keeps_every_contributing_path() {
    let left = BinaryMatcher::candidates([TEXT, TEXT]).offset(8);
    let right = BinaryMatcher::candidates([TEXT + 8, TEXT + 8]);
    let nodes = run_nodes(&scan_image(), left.intersect(right), ()).unwrap();

    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].parents().len(), 4);
    assert!(matches!(
        nodes[0].parents()[0].as_ref(),
        Contributor::Left(_)
    ));
    assert!(matches!(
        nodes[0].parents()[3].as_ref(),
        Contributor::Right(_)
    ));
}

#[test]
fn expansions_share_one_immutable_parent_without_cloning_its_value() {
    struct Source(String);
    let matcher =
        Matcher::items::<Source>().expand(|node| vec![node.value.0.len(), node.value.0.len() + 1]);
    let nodes = run_nodes(&scan_image(), matcher, vec![Source("source".into())]).unwrap();

    assert_eq!(*nodes[0].value, 6);
    assert_eq!(*nodes[1].value, 7);
    assert!(std::sync::Arc::ptr_eq(
        &nodes[0].parents()[0],
        &nodes[1].parents()[0]
    ));
    assert_eq!(nodes[0].parent().value.0, "source");
}

#[test]
fn context_expansion_preserves_order_after_empty_emissions() {
    struct Source(u64);
    let matcher = Matcher::items::<Source>()
        .with_context()
        .expand(|(ctx, node)| {
            if node.value.0 == 0 {
                Vec::new()
            } else {
                vec![ctx.image().base_address + node.value.0; 2]
            }
        });
    let nodes = run_nodes(
        &scan_image(),
        matcher,
        vec![Source(2), Source(0), Source(1)],
    )
    .unwrap();

    assert_eq!(
        nodes.iter().map(|node| *node.value).collect::<Vec<_>>(),
        [BASE + 2, BASE + 2, BASE + 1, BASE + 1]
    );
    assert_eq!(nodes[0].parent().value.0, 2);
    assert_eq!(nodes[2].parent().value.0, 1);
    assert!(std::sync::Arc::ptr_eq(
        &nodes[0].parents()[0],
        &nodes[1].parents()[0]
    ));
    assert!(!std::sync::Arc::ptr_eq(
        &nodes[0].parents()[0],
        &nodes[2].parents()[0]
    ));
}

#[test]
fn fallible_context_expansion_stops_after_the_first_error() {
    let matcher = BinaryMatcher::candidates([0, 1, 2, 3])
        .with_context()
        .try_expand(|(_, node)| match *node.value {
            0 => Ok(Vec::new()),
            1 => Ok(vec![1, 1]),
            2 => Err(ResolveError::new_msg("expansion failed")),
            _ => panic!("error must skip later candidates"),
        })
        .map(|_| -> u64 { panic!("error must skip downstream transformations") });
    let error = run_nodes(&scan_image(), matcher, ()).unwrap_err();

    assert_eq!(error.to_string(), "expansion failed");
}

#[test]
fn optional_maps_drop_values_without_losing_surviving_parents() {
    let matcher = BinaryMatcher::candidates([1, 2, 3])
        .map_filter(|node| (*node.value != 2).then_some(*node.value * 10));
    let nodes = run_nodes(&scan_image(), matcher, ()).unwrap();

    assert_eq!(
        nodes
            .iter()
            .map(|node| (*node.value, *node.parent().value))
            .collect::<Vec<_>>(),
        [(10, 1), (30, 3)]
    );
}

#[test]
fn context_optional_maps_and_expansions_retain_non_clone_parents() {
    struct Source(u64);
    let matcher = Matcher::items::<Source>()
        .with_context()
        .map_filter(|(_, node)| Some(node.value.0))
        .with_context()
        .expand(|(_, node)| vec![*node.value, *node.value + 1]);
    let nodes = run_nodes(&scan_image(), matcher, vec![Source(TEXT)]).unwrap();

    assert_eq!(nodes[1].parent().parent().value.0, TEXT);
    assert_eq!(*nodes[1].value, TEXT + 1);
}

#[test]
fn transform_all_shares_the_complete_input_collection() {
    let matcher =
        Matcher::items::<String>().transform_all(|nodes| vec![nodes.len(), nodes[0].value.len()]);
    let nodes = run_nodes(&scan_image(), matcher, vec!["source".into()]).unwrap();

    assert_eq!(*nodes[0].value, 1);
    assert_eq!(*nodes[1].value, 6);
    assert!(std::sync::Arc::ptr_eq(
        &nodes[0].parents()[0],
        &nodes[1].parents()[0]
    ));
    assert_eq!(nodes[0].parent()[0].value.as_str(), "source");
}

#[test]
fn reused_nodes_and_filters_share_values_without_restarting_ancestry() {
    struct Source(u64);
    let source = Matcher::items::<Source>().map(|node| node.value.0);
    let original = run_nodes(&scan_image(), source, vec![Source(TEXT)]).unwrap();
    let matcher = Matcher::from_nodes(&original)
        .with_context()
        .filter(|(_, node)| *node.value == TEXT)
        .first();
    let node = run_nodes(&scan_image(), matcher, ()).unwrap();

    assert!(std::sync::Arc::ptr_eq(&node.value, &original[0].value));
    assert!(std::sync::Arc::ptr_eq(
        &node.parents()[0],
        &original[0].parents()[0]
    ));
    assert_eq!(node.parent().value.0, TEXT);
}

#[test]
fn fork_retains_both_branches_as_typed_parents() {
    let matcher = BinaryMatcher::address(TEXT)
        .first()
        .fork(BinaryMatcher::address(TEXT + 8));
    let node = run_nodes(&scan_image(), matcher, ()).unwrap();

    assert_eq!(*node.parent().0.value, TEXT);
    assert_eq!(*node.parent().1[0].value, TEXT + 8);
    assert!(std::sync::Arc::ptr_eq(&node.value, &node.parents()[0]));
}

#[test]
fn then_reuses_non_clone_values_via_shared_nodes() {
    struct Source(u64);
    let first = Matcher::items::<Source>();
    let next = Matcher::nodes::<Source, ()>().map(|node| node.value.0 + 1);
    let node = run_nodes(&scan_image(), first.then(next).first(), vec![Source(TEXT)]).unwrap();

    assert_eq!(*node.value, TEXT + 1);
    assert_eq!(node.parent().outer[0].value.0, TEXT);
    assert_eq!(node.parent().inner.value.0, TEXT);
}

#[test]
fn composed_inner_merges_preserve_all_outer_and_inner_paths() {
    let matcher = BinaryMatcher::address(10)
        .flat_map(|outer| {
            let value = *outer.value;
            BinaryMatcher::candidates([value, value])
                .map(|node| *node.value + 1)
                .ensure_one()
        })
        .first();
    let node = run_nodes(&scan_image(), matcher, ()).unwrap();

    assert_eq!(*node.value, 11);
    assert_eq!(node.parents().len(), 2);
    assert_eq!(*node.parents()[0].outer.value, 10);
    assert_eq!(*node.parents()[1].inner.value, 10);
}

#[test]
fn uniqueness_and_sets_need_no_clone_debug_or_equality_on_ancestors() {
    struct Source(String);
    let matcher = Matcher::items::<Source>()
        .map(|node| node.value.0.len())
        .ensure_one();
    let node = run_nodes(
        &scan_image(),
        matcher,
        vec![Source("one".into()), Source("two".into())],
    )
    .unwrap();

    assert_eq!(*node.value, 3);
    assert_eq!(node.parents().len(), 2);
    assert_eq!(node.parents()[0].value.0, "one");
    assert_eq!(node.parents()[1].value.0, "two");

    let original = Matcher::from_nodes([node]);
    let union = original.clone().union(original);
    let nodes = run_nodes(&scan_image(), union, ()).unwrap();

    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].parents().len(), 4);
}

#[test]
fn async_sources_have_unit_parents_and_maps_keep_them() {
    let matcher = Matcher::from_async(|input: String, _| Box::pin(async move { Ok(vec![input]) }))
        .map(|node| node.value.len())
        .first();
    let node = run_nodes(&scan_image(), matcher, "source".into()).unwrap();

    assert_eq!(*node.value, 6);
    assert_eq!(node.parent().value.as_str(), "source");
    assert_eq!(node.parent().parent(), &());
}

#[test]
fn node_clones_share_non_clone_values_without_mutating_other_derivations() {
    struct Source(String);
    let node = run_nodes(
        &scan_image(),
        Matcher::new::<Source>(),
        Source("source".into()),
    )
    .unwrap();
    let other = node.clone();

    assert!(std::sync::Arc::ptr_eq(&node.value, &other.value));
    assert!(std::sync::Arc::ptr_eq(
        &node.parents()[0],
        &other.parents()[0]
    ));
    assert_eq!(node.value.0, "source");
}
