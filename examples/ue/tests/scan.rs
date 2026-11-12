use super::super::scan;
use super::*;
use patternsleuth::resolvers::eval;

#[test]
#[cfg(any(feature = "image-pe", feature = "image-elf"))]
fn tagged_scan_preserves_pattern_capture_offset() {
    let image = image(vec![0x90, 0xaa, 0xbb]);
    let pattern = Pattern::new("AA | BB").unwrap();
    let matches = eval(&image, |ctx| {
        Box::pin(async move {
            binary_bloodhound::BinaryMatcher::tagged_capture_patterns([("target", pattern)])?
                .resolve(ctx)
                .await
        })
    })
    .unwrap();

    assert_eq!(*matches[0].tag, "target");
    assert_eq!(
        matches.iter().map(|node| node.address).collect::<Vec<_>>(),
        [0x1002]
    );
}

#[test]
fn multi_pattern_scan_preserves_pattern_order_duplicates_and_capture_offsets() {
    let image = image(vec![0xaa, 0xbb, 0xaa]);
    let matches = eval(&image, |ctx| {
        Box::pin(scan::scan_patterns(ctx, ["AA | BB", "AA", "AA"]))
    });

    assert_eq!(matches, [0x1001, 0x1000, 0x1002, 0x1000, 0x1002]);
}

#[test]
fn multi_pattern_scan_accepts_empty_collections() {
    let image = image(vec![0xaa]);
    let matches = eval(&image, |ctx| {
        Box::pin(scan::scan_patterns::<Pattern>(ctx, []))
    });

    assert!(matches.is_empty());
}

#[test]
#[cfg(any(feature = "image-pe", feature = "image-elf"))]
fn tagged_scan_pairs_each_match_with_its_tag() {
    let image = image(vec![0xaa, 0xbb, 0xaa]);
    let matches = eval(&image, |ctx| {
        Box::pin(async move {
            BinaryMatcher::tagged_capture_patterns([(7, Pattern::new("AA").unwrap())])?
                .resolve(ctx)
                .await
        })
    })
    .unwrap();

    assert_eq!(
        matches
            .iter()
            .map(|node| (*node.tag, node.address))
            .collect::<Vec<_>>(),
        [(7, 0x1000), (7, 0x1002)]
    );
}
