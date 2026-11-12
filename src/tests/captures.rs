use crate::{Capture, PatternMatch};

#[test]
fn captured_sources_retain_pattern_tags_order_and_non_clone_tag_values() {
    struct Tag(u64);
    let mut text = vec![0x90; 256];
    text[..2].copy_from_slice(&[0xaa, 0xbb]);
    text[8..10].copy_from_slice(&[0xaa, 0xbb]);
    let matcher =
        BinaryMatcher::tagged_capture_patterns([(Tag(1), "AA [ BB ]"), (Tag(2), "AA [ BB ]")])
            .unwrap();
    let nodes: Vec<Trace<PatternMatch<Tag>>> = run_nodes(&image(text), matcher, ()).unwrap();

    assert_eq!(
        nodes
            .iter()
            .map(|node| (node.tag.0, node.address()))
            .collect::<Vec<_>>(),
        [(1, TEXT), (1, TEXT + 8), (2, TEXT), (2, TEXT + 8)]
    );
    assert_eq!(nodes[0].captures[0].address, TEXT + 1);
    assert_eq!(nodes[0].captures[0].data, [0xbb]);
    assert_eq!(nodes[0].parent(), &());
    assert!(std::sync::Arc::ptr_eq(&nodes[0].tag, &nodes[1].tag));
    assert!(std::sync::Arc::ptr_eq(&nodes[0].pattern, &nodes[1].pattern));
    assert!(!std::sync::Arc::ptr_eq(&nodes[0].tag, &nodes[2].tag));
}

#[test]
fn capture_sources_handle_result_markers_and_own_bytes_after_image_drop() {
    let node = {
        let mut text = vec![0x90; 256];
        relative(&mut text, 8, &[0xe8], TEXT + 64);
        let matcher = BinaryMatcher::capture_patterns(["E8 | [ ?? ?? ?? ?? ]"])
            .unwrap()
            .first();
        run_nodes(&image(text), matcher, ()).unwrap()
    };

    assert_eq!(node.address, TEXT + 9);
    assert_eq!(node.start, TEXT + 8);
    assert_eq!(node.captures[0].address, TEXT + 9);
    assert_eq!(node.captures[0].rip4().unwrap(), TEXT + 64);
}

#[test]
fn captures_support_nested_empty_and_absent_capture_groups() {
    let mut text = vec![0x90; 256];
    text[..2].copy_from_slice(&[0xaa, 0xbb]);
    let matcher = BinaryMatcher::capture_patterns(["[ AA [ BB ] ] [ ]", "AA BB"]).unwrap();
    let nodes = run_nodes(&image(text), matcher, ()).unwrap();

    assert_eq!(
        nodes[0]
            .captures
            .iter()
            .map(|capture| capture.data.as_slice())
            .collect::<Vec<_>>(),
        [&[0xbb][..], &[0xaa, 0xbb], &[]]
    );
    assert_eq!(nodes[0].captures[2].address, TEXT + 2);
    assert!(nodes[1].captures.is_empty());
}

#[test]
fn capture_sources_preserve_borrowed_tags_and_report_invalid_pattern_indices() {
    let tag = String::from("tag");
    let matcher = BinaryMatcher::tagged_capture_patterns([(&tag, "90")])
        .unwrap()
        .first();
    let node = run_nodes(&scan_image(), matcher, ()).unwrap();
    let error = BinaryMatcher::capture_patterns(["90", "?"]).err().unwrap();

    assert!(std::ptr::eq(*node.tag, &tag));
    assert!(error.to_string().starts_with("invalid pattern at index 1:"));
}

#[test]
fn capture_sources_accept_empty_inputs_and_missing_matches() {
    for patterns in [vec![], vec!["AA [ BB ]"]] {
        let nodes = run_nodes(
            &image(vec![0x90; 256]),
            BinaryMatcher::capture_patterns(patterns).unwrap(),
            (),
        )
        .unwrap();

        assert!(nodes.is_empty());
    }
}

#[test]
fn capture_sources_keep_complete_matches_within_nested_bounds() {
    let mut text = vec![0x90; 256];
    text[6..8].copy_from_slice(&[0xaa, 0xbb]);
    text[14..16].copy_from_slice(&[0xaa, 0xbb]);
    let matcher = functions(&[(TEXT, TEXT + 16)]).sub(
        functions(&[(TEXT, TEXT + 15)])
            .sub(BinaryMatcher::capture_patterns(["AA | [ BB ]"]).unwrap()),
    );
    let nodes = run_nodes(&image(text), matcher, ()).unwrap();

    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].address, TEXT + 7);
    assert_eq!(nodes[0].captures[0].data, [0xbb]);
}

#[test]
fn capture_decoding_checks_widths_signed_targets_and_overflow() {
    let negative = Capture {
        address: 100,
        data: (-8_i32).to_le_bytes().to_vec(),
    };
    let wide = Capture {
        address: 0,
        data: 42_u64.to_le_bytes().to_vec(),
    };
    let short = Capture {
        address: 0,
        data: vec![1],
    };
    let overflowing = Capture {
        address: u64::MAX,
        data: vec![0; 4],
    };
    let underflowing = Capture {
        address: 0,
        data: (-8_i32).to_le_bytes().to_vec(),
    };

    assert_eq!(negative.rip4().unwrap(), 96);
    assert_eq!(negative.u32().unwrap(), u32::MAX - 7);
    assert_eq!(wide.u64().unwrap(), 42);
    assert!(short.u32().is_err());
    assert!(wide.rip4().is_err());
    assert!(overflowing.rip4().is_err());
    assert!(underflowing.rip4().is_err());
}

#[test]
fn malformed_capture_ranges_return_errors_instead_of_panicking() {
    let mut pattern = Pattern::new("90").unwrap();
    pattern.captures.push(0..2);
    let matcher = BinaryMatcher::capture_patterns([pattern]).unwrap();
    let error = run_nodes(&scan_image(), matcher, ()).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("capture range 0..2 outside matched pattern")
    );
}
