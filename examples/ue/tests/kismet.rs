use super::*;

fn append_exec_step(bytes: &mut Vec<u8>, layout: usize, targets: (u64, u64)) {
    let signatures = [
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ?? 33 FF 33 C0 49 8B F0 48 8B DA 48 8B CA 48 89 7C 24 20 48 89 7C 24 28 48 39 42 20 74 10 48 8B 52 18 4C 8D 44 24 20 E8 [ ?? ?? ?? ?? ] EB 1C 4C 8B 82 80 00 00 00 49 8B 40 ?? 48 89 82 80 00 00 00 48 8D 54 24 20 E8 [ ?? ?? ?? ?? ] 48 8B 43 20 48 8D 4C 24 20 48 85 C0",
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ?? 33 FF 49 8B F0 48 8B DA 48 89 7C 24 20 48 ?? ?? ?? ?? ?? ?? ?? 48 39 7A 20 74 10 48 8B 52 18 4C 8D 44 24 20 E8 [ ?? ?? ?? ?? ] EB 1C 4C 8B 82 80 00 00 00 49 8B 40 ?? 48 89 82 80 00 00 00 48 8D 54 24 20 E8 [ ?? ?? ?? ?? ] 48 8B 43 20 48 8D 4C 24 20 48 85 C0 40 0F",
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 33 ?? 49 8B F0 48 89 ?? 24 20 48 8B ?? 48 89 ?? 24 28 E8 [ ?? ?? ?? ?? ] 48 8B ?? 48 39 ?? 20 74 10 48 8B ?? 18 4C 8D 44 24 20 E8 ?? ?? ?? ?? EB 1C 4C 8B ?? ?? 00 00 00 48 8D 54 24 20 49 8B 40 20 48 89 ?? ?? 00 00 00 E8 [ ?? ?? ?? ?? ] 48 8B ?? 20 48",
        "41 56 53 01001??? 83 ec 18 01001??? 89 d6 01001??? 89 f3 0f 57 c0 0f 29 04 ??100??? e8 ?? ?? ?? ?? 01001??? 83 7b 20 00 74 ?? 01001??? 8b 73 18 01001??? 89 e2 01001??? 89 df e8 [ ?? ?? ?? ?? ] eb ?? 01001??? 8b 93 88 00 00 00 01001??? 8b 42 20 01001??? 89 83 88 00 00 00 01001??? 89 e6 01001??? 89 df e8 [ ?? ?? ?? ?? ]",
    ];
    let pattern = Pattern::new(signatures[layout]).unwrap();
    let start = bytes.len();
    bytes.extend(&pattern.simple.sig);
    for (range, target) in pattern.captures.iter().zip([targets.0, targets.1]) {
        let offset = start + range.start;
        let displacement = i32::try_from(target as i64 - (0x1000 + offset + 4) as i64).unwrap();
        bytes[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
    }
    bytes.extend([0x90; 16]);
}

#[test]
fn exec_step_capture_pipeline_matches_all_upstream_layouts_and_equal_duplicates() {
    for layouts in [
        vec![0],
        vec![1],
        vec![2],
        vec![3],
        vec![0, 0],
        vec![0, 1, 2, 3],
    ] {
        let mut bytes = Vec::new();
        for layout in layouts {
            append_exec_step(&mut bytes, layout, (0x800, 0x3000));
        }
        let image = image(bytes);
        let result = image
            .resolve(models::kismet::FFrameStepViaExec::resolver())
            .unwrap();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::kismet::FFrameStepViaExec::resolver())
            .unwrap();

        assert_eq!(
            (result.step, result.step_explicit_property),
            (0x800, 0x3000)
        );
        assert_eq!(
            (result.step, result.step_explicit_property),
            (upstream.step, upstream.step_explicit_property)
        );
    }
}

#[test]
fn exec_step_capture_pipeline_discards_ambiguous_signatures_before_fallback() {
    let mut bytes = Vec::new();
    append_exec_step(&mut bytes, 0, (0x3000, 0x3100));
    append_exec_step(&mut bytes, 0, (0x3200, 0x3300));
    append_exec_step(&mut bytes, 3, (0x3400, 0x3500));
    let image = image(bytes);
    let result = image
        .resolve(models::kismet::FFrameStepViaExec::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::kismet::FFrameStepViaExec::resolver())
        .unwrap();

    assert_eq!(
        (result.step, result.step_explicit_property),
        (0x3400, 0x3500)
    );
    assert_eq!(
        (result.step, result.step_explicit_property),
        (upstream.step, upstream.step_explicit_property)
    );
}

#[test]
fn exec_step_capture_pipeline_rejects_missing_and_conflicting_successes() {
    for layouts in [vec![], vec![0, 0], vec![0, 3]] {
        let mut bytes = Vec::new();
        for (index, layout) in layouts.into_iter().enumerate() {
            append_exec_step(&mut bytes, layout, (0x3000 + index as u64 * 0x100, 0x4000));
        }
        let image = image(bytes);
        let result = image.resolve(models::kismet::FFrameStepViaExec::resolver());
        let upstream =
            image.resolve(patternsleuth::resolvers::unreal::kismet::FFrameStepViaExec::resolver());

        assert!(result.is_err());
        assert!(upstream.is_err());
    }
}
