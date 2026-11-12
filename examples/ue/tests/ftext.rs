use super::*;

fn write_ftext_match(bytes: &mut [u8], offset: usize, layout: usize, target: u64) {
    let signatures = [
        "40 53 48 83 ec ?? 48 8b d9 e8 [ ?? ?? ?? ?? ] 83 4b ?? 12 48 8b c3 48 83 ?? ?? 5b c3",
        "eb 12 48 8d ?? 24 ?? e8 [ ?? ?? ?? ?? ] ?? 02 00 00 00 48 8b 10 48 89 17",
        "eb 12 48 8d ?? 24 ?? e8 [ ?? ?? ?? ?? ] ?? 02 00 00 00 48 8b 10 89",
        "48 85 c9 74 13 f0 83 41 08 01 eb 0c 48 89 df e8 [ ?? ?? ?? ?? ] 48 8d 43 10",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 48 89 7C 24 ?? 41 54 41 56 41 57 48 83 EC 40 4C 8B F1 48 8B F2",
        "41 57 41 56 41 54 56 57 55 53 48 83 EC 40 48 89 D7 48 89 CE 48 8B 0D",
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC ?? 48 8D 05 ?? ?? ?? ?? 33 F6 48 8B D9 48 89 44 24",
    ];
    let targets = if layout < 4 { &[target][..] } else { &[] };
    write_pattern(bytes, offset, signatures[layout], targets);
}

#[test]
fn ftext_capture_pipeline_matches_indirect_and_direct_signatures() {
    for layout in 0..7 {
        let mut bytes = vec![0x90; 0x400];
        write_ftext_match(&mut bytes, 0x100, layout, 0x800);
        let image = image(bytes);
        let result = image
            .resolve(models::ftext::FTextFString::resolver())
            .unwrap();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::ftext::FTextFString::resolver())
            .unwrap();

        assert_eq!(result.0, if layout < 4 { 0x800 } else { 0x1100 });
        assert_eq!(result.0, upstream.0);
    }
}

#[test]
fn ftext_capture_pipeline_merges_equal_direct_and_indirect_matches() {
    for second_layout in [0, 4, 5, 6] {
        let mut bytes = vec![0x90; 0x400];
        write_ftext_match(&mut bytes, 0x100, 0, 0x1300);
        write_ftext_match(&mut bytes, 0x300, second_layout, 0x1300);
        let image = image(bytes);
        let result = image
            .resolve(models::ftext::FTextFString::resolver())
            .unwrap();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::ftext::FTextFString::resolver())
            .unwrap();

        assert_eq!(result.0, 0x1300);
        assert_eq!(result.0, upstream.0);
    }
}

#[test]
fn ftext_capture_pipeline_preserves_missing_and_conflicting_errors() {
    for layouts in [vec![], vec![0, 0], vec![4, 5], vec![0, 1, 2, 3, 4, 5, 6]] {
        let mut bytes = vec![0x90; 0x400];
        for (index, layout) in layouts.into_iter().enumerate() {
            write_ftext_match(
                &mut bytes,
                index * 0x80,
                layout,
                0x3000 + index as u64 * 0x100,
            );
        }
        let image = image(bytes);
        let result = image
            .resolve(models::ftext::FTextFString::resolver())
            .unwrap_err();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::ftext::FTextFString::resolver())
            .unwrap_err();

        assert_eq!(result.to_string(), upstream.to_string());
    }
}
