use super::*;
use object::SectionKind;
use patternsleuth::{
    Memory, NamedMemorySection,
    image::{Image, ImageType},
    resolvers::eval,
    scanner::Pattern,
};

#[test]
fn factory_list_has_all_resolvers_without_duplicate_names() {
    let names: std::collections::HashSet<_> =
        factories().iter().map(|factory| factory().name).collect();

    assert_eq!(names.len(), 58);
}

#[cfg(any(feature = "image-pe", feature = "image-elf"))]
pub(super) fn image(mut bytes: Vec<u8>) -> Image<'static> {
    bytes.resize(bytes.len().max(512), 0x90);
    #[cfg(feature = "image-elf")]
    let backend = ImageType::ElfImage(patternsleuth::image::elf::ElfImage { functions: None });
    #[cfg(all(feature = "image-pe", not(feature = "image-elf")))]
    let backend = ImageType::PEImage(patternsleuth::image::pe::PEImage {
        exception_directory_range: 0..0,
        exception_children_cache: Default::default(),
    });
    Image::from_memory(
        0x1000,
        Memory::from_sections(vec![NamedMemorySection::new(
            ".text".into(),
            0x1000,
            SectionKind::Text,
            bytes,
        )]),
        backend,
    )
}

#[test]
#[cfg(any(feature = "image-pe", feature = "image-elf"))]
fn tagged_scan_preserves_pattern_capture_offset() {
    let image = image(vec![0x90, 0xaa, 0xbb]);
    let pattern = Pattern::new("AA | BB").unwrap();
    let (tag, _, matches) = eval(&image, |ctx| {
        Box::pin(scan::scan_tagged(ctx, "target", pattern))
    });

    assert_eq!(tag, "target");
    assert_eq!(matches, [0x1002]);
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

fn blueprint_init_bytes(second_class_target: u64) -> Vec<u8> {
    fn write_pattern(bytes: &mut [u8], offset: usize, signature: &str, targets: &[u64]) {
        let pattern = Pattern::new(signature).unwrap();
        let end = offset + pattern.simple.sig.len();
        bytes[offset..end].copy_from_slice(&pattern.simple.sig);
        assert_eq!(pattern.captures.len(), targets.len());
        for (range, target) in pattern.captures.iter().zip(targets) {
            let at = offset + range.start;
            let displacement = i32::try_from(*target as i64 - (0x1000 + at + 4) as i64).unwrap();
            bytes[at..at + 4].copy_from_slice(&displacement.to_le_bytes());
        }
    }

    let mut bytes = vec![0x90; 0x1000];
    for (index, class_target) in [0x3000, second_class_target].into_iter().enumerate() {
        let string_offset = 0x800 + index * 0x100;
        let string = util::utf16("UKismetStringTableLibrary\0");
        bytes[string_offset..string_offset + string.len()].copy_from_slice(&string);
        let string_address = 0x1000 + string_offset as u64;
        write_pattern(
            &mut bytes,
            0x100 + index * 0x40,
            "41 b9 ?? ?? ?? ?? 48 8d 15 [ ?? ?? ?? ?? ] 41 b8 28 00 00 00 48 8d 0d ?? ?? ?? ?? e9 [ ?? ?? ?? ?? ]",
            &[string_address, class_target],
        );
        write_pattern(
            &mut bytes,
            0x200 + index * 0x80,
            "48 83 ec 48 33 c0 4c 8d 0d ?? ?? ?? ?? 48 89 44 24 30 4c 8d 05 [ ?? ?? ?? ?? ] 48 89 44 24 28 48 8d 15 [ ?? ?? ?? ?? ] 48 8d 0d [ ?? ?? ?? ?? ] 88 44 24 20 e8 [ ?? ?? ?? ?? ] 48 83 c4 48 c3",
            &[string_address, 0x1500, 0x1400, 0x3010],
        );
    }
    write_pattern(
        &mut bytes,
        0x400,
        "48 83 ec 28 48 8b 05 ?? ?? ?? ?? 48 85 c0 75 1a 48 8d 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? e8 [ ?? ?? ?? ?? ] 48 8b 05 ?? ?? ?? ?? 48 83 c4 28 c3",
        &[0x3020],
    );
    write_pattern(
        &mut bytes,
        0x500,
        "4c 8b dc 48 81 ec 88 00 00 00 48 8b 05 ?? ?? ?? ?? 48 85 c0 0f 85 90 00 00 00 33 c9 48 8d 05 [ ?? ?? ?? ?? ] 49 89 4b f0 4c 8d 0d ?? ?? ?? ?? 88 4c 24 70 4c 8d 05 ?? ?? ?? ?? 49 89 43 e0 48 8d 15 ?? ?? ?? ?? 48 8d 05 [ ?? ?? ?? ?? ] 49 89 43 d8 48 8d 05 ?? ?? ?? ?? 49 89 43 d0 48 8d 05 ?? ?? ?? ?? 49 89 43 c8 48 8d 05 ?? ?? ?? ?? 49 89 43 c0 48 8d 05 ?? ?? ?? ?? 49 89 43 b8 49 89 4b b0 48 8d 0d ?? ?? ?? ?? c7 44 24 30 ?? ?? ?? ?? c7 44 24 28 ?? ?? ?? ?? c7 44 24 20 ?? ?? ?? ?? e8 [ ?? ?? ?? ?? ] 48 8b 05 ?? ?? ?? ?? 48 81 c4 88 00 00 00 c3",
        &[0x3040, 0x3050, 0x3030],
    );
    bytes
}

#[test]
fn blueprint_capture_pipelines_match_upstream_with_duplicate_targets() {
    let image = image(blueprint_init_bytes(0x3000));
    let result = image
        .resolve(models::blueprint::BlueprintLibraryInit::resolver())
        .unwrap();
    let upstream = image
        .resolve(
            patternsleuth::resolvers::unreal::blueprint_library::BlueprintLibraryInit::resolver(),
        )
        .unwrap();

    assert_eq!(
        result,
        models::blueprint::BlueprintLibraryInit {
            uclass_compiled_in_defer: 0x3000,
            uobject_compiled_in_defer: 0x3010,
            construct_uclass: 0x3020,
            get_private_static_class_body: 0x3030,
            uobject_static_class: 0x3040,
            ublueprint_function_library_static_class: 0x3050,
        }
    );
    assert_eq!(format!("{result:?}"), format!("{upstream:?}"));
}

#[test]
fn blueprint_capture_pipelines_reject_missing_ambiguous_and_invalid_wrappers() {
    let mut invalid_wrapper = blueprint_init_bytes(0x3000);
    invalid_wrapper[0x400] = 0x90;
    let mut missing_object = blueprint_init_bytes(0x3000);
    missing_object[0x200] = 0x90;
    missing_object[0x280] = 0x90;
    for bytes in [
        vec![],
        blueprint_init_bytes(0x3004),
        invalid_wrapper,
        missing_object,
    ] {
        let image = image(bytes);
        let result = image.resolve(models::blueprint::BlueprintLibraryInit::resolver());
        let upstream = image.resolve(
            patternsleuth::resolvers::unreal::blueprint_library::BlueprintLibraryInit::resolver(),
        );

        assert!(result.is_err());
        assert!(upstream.is_err());
    }
}

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

fn append_object_array_layout(bytes: &mut Vec<u8>, operands: [u64; 3]) {
    let start = bytes.len();
    bytes.resize(start + 34, 0x90);
    for (index, target) in operands.into_iter().enumerate() {
        let opcode = if index == 0 {
            [0x8b, 0x05]
        } else {
            [0x2b, 0x05]
        };
        relative(bytes, start + index * 6, &opcode, target);
    }
}

fn append_object_array_address(bytes: &mut Vec<u8>, immediate: bool, target: u32) {
    let signature = if immediate {
        "41 39 ee 0f 8e ?? ?? ?? ?? bf | ?? ?? ?? ?? 48 8b 74 24 10 e8 ?? ?? ?? ?? e9"
    } else {
        "75 ?? 48 ?? ?? 48 8D 0D | ?? ?? ?? ?? E8 ?? ?? ?? ?? 45 33 C9 4C 89 74 24"
    };
    let pattern = Pattern::new(signature).unwrap();
    let start = bytes.len();
    bytes.extend(&pattern.simple.sig);
    let offset = start + pattern.custom_offset;
    let data = if immediate {
        target.to_le_bytes()
    } else {
        i32::try_from(i64::from(target) - (0x1000 + offset + 4) as i64)
            .unwrap()
            .to_le_bytes()
    };
    bytes[offset..offset + 4].copy_from_slice(&data);
    bytes.extend([0x90; 16]);
}

#[test]
fn object_array_capture_pipeline_matches_known_layouts_in_any_operand_order() {
    for layout in [[0x00, 0x24, 0x60], [0x00, 0x24, 0x68], [0x08, 0x20, 0x68]] {
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut bytes = Vec::new();
            append_object_array_layout(&mut bytes, order.map(|index| 0x4000 + layout[index]));
            let image = image(bytes);
            let result = image
                .resolve(models::objects::GUObjectArray::resolver())
                .unwrap();
            let upstream = image
                .resolve(
                    patternsleuth::resolvers::unreal::guobject_array::GUObjectArray::resolver(),
                )
                .unwrap();

            assert_eq!(result.0, 0x4000);
            assert_eq!(result.0, upstream.0);
        }
    }
}

#[test]
fn object_array_pipelines_merge_equal_heuristics_and_skip_unknown_spacing() {
    for sources in [vec![false], vec![true], vec![false, true, false]] {
        let mut bytes = Vec::new();
        for immediate in sources {
            append_object_array_address(&mut bytes, immediate, 0x4000);
        }
        append_object_array_layout(&mut bytes, [0x4000, 0x4024, 0x4060]);
        append_object_array_layout(&mut bytes, [0x5000, 0x5010, 0x5020]);
        let image = image(bytes);
        let result = image
            .resolve(models::objects::GUObjectArray::resolver())
            .unwrap();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::guobject_array::GUObjectArray::resolver())
            .unwrap();

        assert_eq!(result.0, 0x4000);
        assert_eq!(result.0, upstream.0);
    }
}

#[test]
fn object_array_pipelines_reject_empty_unknown_and_conflicting_candidates() {
    let mut unknown = Vec::new();
    append_object_array_layout(&mut unknown, [0x5000, 0x5010, 0x5020]);
    let mut conflicting_addresses = Vec::new();
    append_object_array_address(&mut conflicting_addresses, false, 0x4000);
    append_object_array_address(&mut conflicting_addresses, true, 0x5000);
    let mut conflicting_layouts = Vec::new();
    append_object_array_layout(&mut conflicting_layouts, [0x4000, 0x4024, 0x4060]);
    append_object_array_layout(&mut conflicting_layouts, [0x5000, 0x5024, 0x5060]);
    for bytes in [vec![], unknown, conflicting_addresses, conflicting_layouts] {
        let image = image(bytes);
        let result = image
            .resolve(models::objects::GUObjectArray::resolver())
            .unwrap_err();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::guobject_array::GUObjectArray::resolver())
            .unwrap_err();

        assert_eq!(result.to_string(), upstream.to_string());
    }
}

#[test]
fn engine_version_pipelines_preserve_fallback_priority() {
    for stage in 0..4 {
        let mut bytes = vec![0x90; 128];
        if stage <= 1 {
            bytes[..20].copy_from_slice(&[
                0xc7, 0x43, 0x20, 5, 0, 3, 0, // Version 5.3.
                0x66, 0xc7, 0x43, 0x24, 2, 0, // Patch.
                0xc7, 0x43, 0x28, 123, 0, 0, 0,
            ]);
        }
        if stage <= 2 {
            bytes[32..43].copy_from_slice(&[0xc7, 0x47, 0x20, 4, 0, 26, 0, 0x66, 0x89, 0x6f, 0x24]);
        }
        if stage == 0 {
            bytes.extend(util::utf16("\05.4.2-12345+branch\0"));
        }
        bytes.extend(util::utf16("++UE4+Release-4.25Plus\0"));
        let image = image(bytes);
        let result = image
            .resolve(models::version::EngineVersion::resolver())
            .unwrap();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::engine_version::EngineVersion::resolver())
            .unwrap();
        let expected = [(5, 4), (5, 3), (4, 26), (4, 25)][stage];

        assert_eq!((result.major, result.minor), expected);
        assert_eq!(
            (result.major, result.minor),
            (upstream.major, upstream.minor)
        );
    }
}

#[cfg(feature = "image-pe")]
fn aes_key_bytes(layout: usize, key: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (index, chunk) in key.chunks_exact(4).enumerate() {
        if layout == 0 && index == 2 {
            bytes.extend([0x90; 4]);
        }
        if layout == 2 && index == 4 {
            bytes.extend([0x0f, 0x10, 0x45, 0xd0]);
        }
        if layout == 1 {
            if index == 0 {
                bytes.extend([0xc7, 0x01]);
            } else {
                bytes.extend([0xc7, 0x41, (index * 4) as u8]);
            }
        } else {
            bytes.extend([0xc7, 0x45, 0xd0 + (index * 4) as u8]);
        }
        bytes.extend(chunk);
    }
    if layout == 1 {
        bytes.push(0xc3);
    }
    bytes
}

#[test]
#[cfg(feature = "image-pe")]
fn aes_capture_pipeline_preserves_layouts_order_duplicates_and_placeholder_filtering() {
    let placeholder = *b"\x6f\x16\x80\x73\xb9\xb2\x14\x49\xd7\x42\x24\x17\x00\x06\x8a\xda\xbc\x30\x6f\xa9\xaa\x38\x31\x16\x4d\xee\x8d\xe3\x4e\x0e\xfb\xb0";
    let keys = [std::array::from_fn(|i| i as u8), [0x42; 32], [0xa5; 32]];
    let mut bytes = Vec::new();
    for layout in [2, 1, 0] {
        for key in [keys[layout], placeholder, keys[layout]] {
            bytes.extend(aes_key_bytes(layout, key));
            bytes.extend([0x90; 16]);
        }
    }
    let image = pe_image(bytes);
    let result = image.resolve(models::aes::AESKeys::resolver()).unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::aes::AESKeys::resolver())
        .unwrap();

    assert_eq!(
        result.0.iter().map(|key| key.0).collect::<Vec<_>>(),
        [keys[0], keys[0], keys[1], keys[1], keys[2], keys[2]]
    );
    assert_eq!(format!("{result:?}"), format!("{upstream:?}"));
}

#[test]
#[cfg(feature = "image-pe")]
fn aes_capture_pipeline_accepts_no_keys_and_truncated_instructions() {
    let key = [0x42; 32];
    for bytes in [vec![], aes_key_bytes(0, key)[..54].to_vec()] {
        let image = pe_image(bytes);
        let result = image.resolve(models::aes::AESKeys::resolver()).unwrap();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::aes::AESKeys::resolver())
            .unwrap();

        assert!(result.0.is_empty());
        assert_eq!(format!("{result:?}"), format!("{upstream:?}"));
    }
}

#[test]
fn engine_version_ambiguous_strings_fall_back_to_patterns() {
    let mut bytes = vec![0x90; 64];
    bytes[..11].copy_from_slice(&[0xc7, 0x47, 0x20, 4, 0, 26, 0, 0x66, 0x89, 0x6f, 0x24]);
    bytes.extend(util::utf16("\05.2.1-123+branch\0\05.4.1-456+branch\0"));
    let image = image(bytes);
    let result = image
        .resolve(models::version::EngineVersion::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::engine_version::EngineVersion::resolver())
        .unwrap();

    assert_eq!((result.major, result.minor), (4, 26));
    assert_eq!(
        (result.major, result.minor),
        (upstream.major, upstream.minor)
    );
}

#[test]
fn engine_version_empty_pipeline_keeps_the_pattern_error() {
    let image = image(Vec::new());
    let result = image
        .resolve(models::version::EngineVersion::resolver())
        .unwrap_err();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::engine_version::EngineVersion::resolver())
        .unwrap_err();

    assert_eq!(result.to_string(), upstream.to_string());
}

#[test]
#[cfg(feature = "image-elf")]
fn engine_version_strings_elf_pipeline_matches_upstream() {
    let mut bytes = util::utf16("++UE5+Release-5.3-CL-123\0++UE5+Release-5.3\0Jan 01 2024\0");
    bytes.extend(util::utf16("Jan 99 2024\0"));
    let image = image(bytes);
    let result = image
        .resolve(models::version::EngineVersionStrings::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::engine_version::EngineVersionStrings::resolver())
        .unwrap();

    assert_eq!(result.branch_name, "++UE5+Release-5.3");
    assert_eq!(result.build_date, "Jan 01 2024");
    assert_eq!(result.branch_name, upstream.branch_name);
    assert_eq!(result.build_version, upstream.build_version);
    assert_eq!(result.build_date, upstream.build_date);
}

#[test]
#[cfg(feature = "image-pe")]
fn engine_version_strings_pe_pipeline_keeps_first_success() {
    let mut bytes = vec![0xcc; 512];
    for (base, targets) in [
        (0, [0x1100, 0x1140, 0x1180]),
        (64, [0x9000, 0x1140, 0x9000]),
    ] {
        for (index, target) in targets.into_iter().enumerate() {
            relative(&mut bytes, base + index * 16, &[0x48, 0x8d, 0x05], target);
            bytes[base + index * 16 + 7] = 0xc3;
        }
    }
    for (offset, string) in [
        (256, "++UE5+Release-5.3\0"),
        (320, "Jan 01 2024\0"),
        (384, "5.3.2-123+branch\0"),
    ] {
        let string = util::utf16(string);
        bytes[offset..offset + string.len()].copy_from_slice(&string);
    }
    let image = image(bytes);
    let image = Image::from_memory(
        0x1000,
        image.memory,
        ImageType::PEImage(patternsleuth::image::pe::PEImage {
            exception_directory_range: 0..0,
            exception_children_cache: Default::default(),
        }),
    );
    let result = image
        .resolve(models::version::EngineVersionStrings::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::engine_version::EngineVersionStrings::resolver())
        .unwrap();

    assert_eq!(result.branch_name, upstream.branch_name);
    assert_eq!(result.build_version, upstream.build_version);
    assert_eq!(result.build_date, upstream.build_date);
}

#[test]
fn build_changelist_pipeline_walks_without_roots_and_stops_at_first_success() {
    let mut bytes = vec![0x90; 512];
    for (offset, target) in [(0, 0x1080), (32, 0x9000)] {
        relative(&mut bytes, offset, &[0xe8], target);
        bytes[offset + 5..offset + 8].copy_from_slice(&[0x4c, 0x8b, 0xc0]);
        relative(&mut bytes, offset + 8, &[0x48, 0x8d, 0x15], 0x1100);
        bytes[offset + 15..offset + 21].copy_from_slice(&[0x48, 0x8d, 0x4c, 0x24, 0x20, 0xe8]);
    }
    relative(&mut bytes, 128, &[0x48, 0x8d, 0x05], 0x1140);
    bytes[135] = 0xc3;
    for (offset, string) in [(256, "Build: %s\0"), (320, "main-CL-89524\0")] {
        let string = util::utf16(string);
        bytes[offset..offset + string.len()].copy_from_slice(&string);
    }
    let image = image(bytes);
    let result = image
        .resolve(models::build::BuildChangeList::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::engine_version::BuildChangeList::resolver())
        .unwrap();

    assert_eq!(result.0, "main-CL-89524");
    assert_eq!(result.0, upstream.0);
}

#[test]
fn internal_project_pipeline_keeps_unmapped_and_bss_names_optional() {
    for target in [0x1140, 0x5000, 0x9000] {
        let mut bytes = vec![0x90; 512];
        relative(&mut bytes, 0, &[0x4c, 0x8d, 0x05], target);
        relative(&mut bytes, 7, &[0x48, 0x8d, 0x15], 0x1100);
        bytes[14..20].copy_from_slice(&[0x48, 0x8d, 0x4c, 0x24, 0x20, 0xe8]);
        for (offset, string) in [(256, "UE4-%s\0"), (320, "MyProject\0")] {
            let string = util::utf16(string);
            bytes[offset..offset + string.len()].copy_from_slice(&string);
        }
        let image = image(bytes).with_section(NamedMemorySection::new(
            ".bss".into(),
            0x5000,
            SectionKind::UninitializedData,
            vec![0; 32],
        ));
        let result = image
            .resolve(models::build::InternalProjectName::resolver())
            .unwrap();
        let upstream = image
            .resolve(
                patternsleuth::resolvers::unreal::engine_version::InternalProjectName::resolver(),
            )
            .unwrap();

        assert_eq!(result.internal_project_name, target);
        assert_eq!(
            result.compiled_in_project_name.as_deref(),
            (target == 0x1140).then_some("MyProject")
        );
        assert_eq!(result.internal_project_name, upstream.internal_project_name);
        assert_eq!(
            result.compiled_in_project_name,
            upstream.compiled_in_project_name
        );
    }
}

#[test]
fn static_custom_version_pipeline_preserves_capture_variants_and_deduplication() {
    let mut bytes = vec![0x90; 512];
    for offset in [0, 64] {
        relative(&mut bytes, offset, &[0x0f, 0x10, 0x05], 0x1100);
        bytes[offset + 7..offset + 10].copy_from_slice(&[0x45, 0x33, 0xc9]);
        relative(&mut bytes, offset + 10, &[0x4c, 0x8d, 0x05], 0x1140);
        bytes[offset + 17..offset + 29].copy_from_slice(&[
            0x33, 0xd2, 0x48, 0x8d, 0x4c, 0x24, 0x20, 0x0f, 0x29, 0x44, 0x24, 0x20,
        ]);
        relative(&mut bytes, offset + 29, &[0xe8], 0x2000);
    }
    bytes[256..272].copy_from_slice(&[7; 16]);
    let name = util::utf16("ExampleVersion\0");
    bytes[320..320 + name.len()].copy_from_slice(&name);
    let image = image(bytes);
    let result = image
        .resolve(models::custom_versions::StaticCustomVersions::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::engine_version::StaticCustomVersions::resolver())
        .unwrap();

    assert_eq!(result.0.len(), 1);
    assert_eq!(result.0.first().unwrap().name, "ExampleVersion");
    assert_eq!(format!("{result:?}"), format!("{upstream:?}"));
}

#[test]
#[cfg(any(feature = "image-pe", feature = "image-elf"))]
fn tagged_scan_pairs_each_match_with_its_tag() {
    let image = image(vec![0xaa, 0xbb, 0xaa]);
    let matches = eval(&image, |ctx| {
        Box::pin(scan::scan_tagged2(ctx, 7, Pattern::new("AA").unwrap()))
    });

    assert_eq!(matches, [(7, 0x1000), (7, 0x1002)]);
}

#[test]
#[cfg(any(feature = "image-pe", feature = "image-elf"))]
fn native_resolver_matches_upstream_rip_relative_result() {
    let image = image(vec![
        0xcc, 0x48, 0x83, 0xec, 0x28, 0xe8, 0x20, 0, 0, 0, 0x48, 0x8b, 0xc8, 0x48, 0x83, 0xc4,
        0x28, 0x48, 0xff,
    ]);
    let result = image
        .resolve(models::objects::FUObjectHashTablesGet::resolver())
        .unwrap();
    let upstream = image
        .resolve(
            patternsleuth::resolvers::unreal::fuobject_hash_tables::FUObjectHashTablesGet::resolver(
            ),
        )
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x102a);
}

#[test]
#[cfg(feature = "image-elf")]
fn string_reference_pipeline_matches_upstream_root_function() {
    let mut bytes = vec![0x90; 128];
    bytes[..7].copy_from_slice(&[0x48, 0x8d, 0x0d, 121, 0, 0, 0]);
    bytes[16..23].copy_from_slice(&[0x48, 0x8d, 0x0d, 129, 0, 0, 0]);
    bytes.extend(util::utf16("causeevent=\0"));
    bytes.extend(util::utf16("CAUSEEVENT \0"));
    let image = image(bytes);
    let image = Image::from_memory(
        0x1000,
        image.memory,
        ImageType::ElfImage(patternsleuth::image::elf::ElfImage {
            functions: Some(vec![0x1000..0x1200]),
        }),
    );
    let result = image
        .resolve(models::engine::UGameEngineTick::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::game_loop::UGameEngineTick::resolver())
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x1000);
}

fn relative(bytes: &mut [u8], offset: usize, opcode: &[u8], target: u64) {
    bytes[offset..offset + opcode.len()].copy_from_slice(opcode);
    let next = 0x1000 + (offset + opcode.len() + 4) as u64;
    let displacement = i32::try_from(i128::from(target) - i128::from(next)).unwrap();
    bytes[offset + opcode.len()..offset + opcode.len() + 4]
        .copy_from_slice(&displacement.to_le_bytes());
}

#[test]
fn static_fname_keeps_signature_priority_and_first_match_selection() {
    for wide in [false, true] {
        let mut bytes = vec![0x90; 256];
        // The newer signature occurs earlier, but the older signature has priority.
        relative(&mut bytes, 0, &[0x48, 0x8d, 0x15], 0x1100);
        relative(&mut bytes, 7, &[0x48, 0x8d, 0x0d], 0x2000);
        bytes[14] = 0xe9;
        bytes[32..38].copy_from_slice(&[0x41, 0xb8, 1, 0, 0, 0]);
        relative(&mut bytes, 38, &[0x48, 0x8d, 0x15], 0x1100);
        relative(&mut bytes, 45, &[0x48, 0x8d, 0x0d], 0x3000);
        bytes[52] = 0xe9;
        if wide {
            bytes.extend(util::utf16("GLSL_ES3_1_ANDROID\0"));
        } else {
            bytes.extend(b"GLSL_ES3_1_ANDROID\0");
        }
        let image = image(bytes);
        let result = image
            .resolve(models::fname::StaticFNameConst::resolver())
            .unwrap();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::fname::StaticFNameConst::resolver())
            .unwrap();

        assert_eq!(result.0, upstream.0);
        assert_eq!(result.0, 0x3000);
    }
}

#[test]
fn fname_pool_legacy_getter_matches_upstream() {
    for size in [4, 8] {
        let mut bytes = vec![0x90; 64];
        bytes[..4].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]);
        relative(&mut bytes, 4, &[0x48, 0x8b, 0x05], 0x2000);
        bytes[11..22]
            .copy_from_slice(&[0x48, 0x85, 0xc0, 0x75, 0x01, 0xb9, 0x08, size, 0, 0, 0x90]);
        let image = image(bytes);
        let result = image.resolve(models::fname::FNamePool::resolver()).unwrap();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::fname::FNamePool::resolver())
            .unwrap();

        assert_eq!(result.0, upstream.0);
        assert_eq!(result.0, 0x2000);
    }
}

#[test]
#[cfg(feature = "image-elf")]
fn fname_to_string_elf_matches_upstream_call_target() {
    let mut bytes = vec![0x90; 256];
    relative(&mut bytes, 0, &[0xe8], 0x2000);
    bytes[5..16].copy_from_slice(&[
        0x49, 0x8b, 0x5f, 0x10, 0x48, 0x8d, 0x7c, 0x24, 0x30, 0xbe, 0,
    ]);
    bytes[15..19].copy_from_slice(&0x1100_u32.to_le_bytes());
    bytes.extend(util::utf16("SkySphereMesh\0"));
    let image = image(bytes);
    let result = image
        .resolve(models::fname::FNameToString::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::fname::FNameToString::resolver())
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x2000);
}

fn object_image(message: &str, wide: bool) -> Image<'static> {
    let mut bytes = vec![0x90; 256];
    relative(&mut bytes, 0, &[0x48, 0x8d, 0x0d], 0x1100);
    relative(&mut bytes, 64, &[0xe8], 0x1000);
    if wide {
        bytes.extend(util::utf16(message));
    } else {
        bytes.extend(message.as_bytes());
    }
    let image = image(bytes);
    #[cfg(feature = "image-elf")]
    let backend = ImageType::ElfImage(patternsleuth::image::elf::ElfImage {
        functions: Some(vec![0x1000..0x1040, 0x1040..0x1080]),
    });
    #[cfg(all(feature = "image-pe", not(feature = "image-elf")))]
    let backend = ImageType::PEImage(patternsleuth::image::pe::PEImage {
        exception_directory_range: 0x2000..0x2018,
        exception_children_cache: Default::default(),
    });
    let image = Image::from_memory(0x1000, image.memory, backend);
    #[cfg(all(feature = "image-pe", not(feature = "image-elf")))]
    let image = image
        .with_section(NamedMemorySection::new(
            ".pdata".into(),
            0x2000,
            SectionKind::ReadOnlyData,
            [0_u32, 0x40, 0x2000, 0x40, 0x80, 0x2004]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>(),
        ))
        .with_section(NamedMemorySection::new(
            ".xdata".into(),
            0x3000,
            SectionKind::ReadOnlyData,
            [1, 0, 0, 0].repeat(2),
        ));
    image
}

#[test]
fn console_manager_pipeline_matches_upstream_with_both_string_anchors() {
    let first = util::utf16("r.DumpingMovie");
    let second = util::utf16("vr.pixeldensity");
    let mut bytes = vec![0x90; 256];
    relative(&mut bytes, 0, &[0x48, 0x8d, 0x15], 0x1100);
    relative(
        &mut bytes,
        16,
        &[0x48, 0x8d, 0x15],
        0x1100 + first.len() as u64,
    );
    bytes.extend(first);
    bytes.extend(second);
    let image = object_image("", true).with_text(bytes).unwrap();
    let result = image
        .resolve(models::engine::ConsoleManagerSingleton::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::ConsoleManagerSingleton::resolver())
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x1000);
}

#[test]
fn object_allocation_pipeline_matches_upstream_for_both_encodings() {
    for wide in [false, true] {
        let image = object_image(
            "Unable to add more objects to disregard for GC pool (Max: %d)\0",
            wide,
        );
        let result = image
            .resolve(models::objects::FUObjectArrayAllocateUObjectIndex::resolver())
            .unwrap();
        let upstream = image.resolve(
            patternsleuth::resolvers::unreal::guobject_array::FUObjectArrayAllocateUObjectIndex::resolver(),
        ).unwrap();

        assert_eq!(result.0, upstream.0);
        assert_eq!(result.0, 0x1000);
    }
}

#[test]
fn object_shutdown_pipeline_matches_upstream_backend_selection() {
    let image = object_image(
        "All UObject delete listeners should be unregistered when shutting down the UObject array\0",
        true,
    );
    let result = image
        .resolve(models::objects::UObjectBaseShutdown::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::guobject_array::UObjectBaseShutdown::resolver())
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(
        result.0,
        if cfg!(feature = "image-elf") {
            0x1040
        } else {
            0x1000
        }
    );
}

#[test]
fn object_free_pipeline_excludes_the_allocation_function() {
    let image = object_image(
        "Unable to add more objects to disregard for GC pool (Max: %d)\0",
        false,
    );
    let mut bytes = image.memory.sections()[0].data().to_vec();
    relative(&mut bytes, 8, &[0x48, 0x8d, 0x0d], 0x1200);
    relative(&mut bytes, 72, &[0x48, 0x8d, 0x0d], 0x1200);
    let image = image.with_text(bytes).unwrap().with_section(NamedMemorySection::new(
        ".rdata".into(), 0x1200, SectionKind::ReadOnlyData,
        b"Removing object (0x%016llx) at index %d but the index points to a different object (0x%016llx)!".to_vec(),
    ));
    let result = image
        .resolve(models::objects::FUObjectArrayFreeUObjectIndex::resolver())
        .unwrap();
    let upstream = image.resolve(
        patternsleuth::resolvers::unreal::guobject_array::FUObjectArrayFreeUObjectIndex::resolver(),
    ).unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x1040);
}

#[cfg(feature = "image-pe")]
fn pe_image(bytes: Vec<u8>) -> Image<'static> {
    let image = image(bytes);
    Image::from_memory(
        0x1000,
        image.memory,
        ImageType::PEImage(patternsleuth::image::pe::PEImage {
            exception_directory_range: 0x2000..0x2018,
            exception_children_cache: Default::default(),
        }),
    )
    .with_section(NamedMemorySection::new(
        ".pdata".into(),
        0x2000,
        SectionKind::ReadOnlyData,
        [0_u32, 0x40, 0x2000, 0x40, 0x80, 0x2004]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>(),
    ))
    .with_section(NamedMemorySection::new(
        ".xdata".into(),
        0x3000,
        SectionKind::ReadOnlyData,
        [1, 0, 0, 0].repeat(2),
    ))
}

#[test]
#[cfg(feature = "image-pe")]
fn engine_tick_set_pipeline_matches_upstream_anchor_intersections() {
    for shared_function in [true, false] {
        let mut bytes = vec![0x90; 256];
        let primary = 0x1000 + bytes.len() as u64;
        bytes.extend(util::utf16("t.IdleWhenNotForeground\0"));
        let secondary_a = 0x1000 + bytes.len() as u64;
        bytes.extend(util::utf16("r.OneFrameThreadLag\0"));
        let secondary_b = 0x1000 + bytes.len() as u64;
        bytes.extend(util::utf16("FEngineLoop::Tick.Benchmarking\0"));
        relative(&mut bytes, 0, &[0x48, 0x8d, 0x0d], primary);
        relative(&mut bytes, 16, &[0x48, 0x8d, 0x0d], primary);
        relative(
            &mut bytes,
            if shared_function { 8 } else { 72 },
            &[0x48, 0x8d, 0x0d],
            secondary_a,
        );
        relative(&mut bytes, 64, &[0x48, 0x8d, 0x0d], secondary_b);
        let image = pe_image(bytes);
        let result = image.resolve(models::engine::FEngineLoopTick::resolver());
        let upstream =
            image.resolve(patternsleuth::resolvers::unreal::game_loop::FEngineLoopTick::resolver());

        if shared_function {
            assert_eq!(result.unwrap().0, upstream.unwrap().0);
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                upstream.unwrap_err().to_string()
            );
        }
    }
}

#[test]
#[cfg(feature = "image-pe")]
fn gengine_pipeline_matches_upstream_register_tracking() {
    let mut bytes = vec![0x90; 256];
    relative(&mut bytes, 0, &[0x48, 0x8d, 0x0d], 0x4000);
    relative(&mut bytes, 7, &[0x4c, 0x8d, 0x05], 0x1100);
    bytes[14] = 0xc3;
    bytes.extend(util::utf16("rhi.DumpMemory\0"));
    let image = pe_image(bytes);
    let result = image.resolve(models::engine::GEngine::resolver()).unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::gengine::GEngine::resolver())
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x4000);
}

#[cfg(feature = "image-pe")]
fn gengine_branch_image(destination: u64) -> Image<'static> {
    let mut bytes = vec![0x90; 256];
    relative(&mut bytes, 0, &[0x48, 0x8d, 0x0d], 0x4000);
    relative(&mut bytes, 7, &[0x0f, 0x84], 0x1000 + 20);
    relative(&mut bytes, 13, &[0xe9], 0x1000 + destination);
    relative(&mut bytes, 20, &[0x48, 0x8d, 0x0d], 0x5000);
    relative(&mut bytes, 27, &[0xe9], 0x1000 + 40);
    relative(&mut bytes, 40, &[0x4c, 0x8d, 0x05], 0x1100);
    relative(&mut bytes, 48, &[0xe9], 0xffff);
    bytes.extend(util::utf16("rhi.DumpMemory\0"));
    pe_image(bytes)
}

#[test]
#[cfg(feature = "image-pe")]
fn gengine_walker_returns_rcx_before_other_paths_can_overwrite_it() {
    let image = gengine_branch_image(40);
    let result = image.resolve(models::engine::GEngine::resolver()).unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::gengine::GEngine::resolver())
        .unwrap();

    // Upstream shares RCX across paths; the fold returns the reaching path's value.
    assert_eq!(result.0, 0x4000);
    assert_eq!(upstream.0, 0x5000);
}

#[test]
#[cfg(feature = "image-pe")]
fn gengine_walker_resumes_queued_paths_after_a_range_stop() {
    let image = gengine_branch_image(48);
    let result = image.resolve(models::engine::GEngine::resolver()).unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::gengine::GEngine::resolver())
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x5000);
}

#[test]
#[cfg(feature = "image-pe")]
fn gengine_walker_does_not_borrow_rcx_from_a_different_path() {
    let mut bytes = vec![0x90; 256];
    relative(&mut bytes, 0, &[0x0f, 0x84], 0x1000 + 24);
    relative(&mut bytes, 6, &[0x48, 0x8d, 0x0d], 0x4000);
    relative(&mut bytes, 13, &[0xe9], 0x1000 + 48);
    relative(&mut bytes, 24, &[0x4c, 0x8d, 0x05], 0x1100);
    bytes[48] = 0xc3;
    bytes.extend(util::utf16("rhi.DumpMemory\0"));
    let image = pe_image(bytes);
    let result = image.resolve(models::engine::GEngine::resolver());
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::gengine::GEngine::resolver())
        .unwrap();

    assert!(result.is_err());
    assert_eq!(upstream.0, 0x4000);
}

#[test]
#[cfg(feature = "image-pe")]
fn gengine_pipeline_requires_r8_at_the_original_reference() {
    let mut bytes = vec![0x90; 256];
    relative(&mut bytes, 0, &[0x48, 0x8d, 0x0d], 0x4000);
    relative(&mut bytes, 7, &[0x4c, 0x8d, 0x05], 0x5000);
    relative(&mut bytes, 14, &[0x48, 0x8d, 0x0d], 0x1100);
    bytes[21] = 0xc3;
    bytes.extend(util::utf16("rhi.DumpMemory\0"));
    let image = pe_image(bytes);
    let error = image
        .resolve(models::engine::GEngine::resolver())
        .unwrap_err();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::gengine::GEngine::resolver())
        .unwrap_err();

    assert_eq!(error.to_string(), upstream.to_string());
}

#[test]
#[cfg(feature = "image-pe")]
fn fname_constructor_keeps_direct_prologue_priority() {
    let mut bytes = vec![0x90; 256];
    let prologue = Pattern::new("48 89 5C 24 08 57 48 83 EC 30 48 8B D9 41 8B F8 33 C9 4C 8B DA 44 8B D1 4C 8B CA 48 85 D2 74 ?? 0F B7 02 66 85 C0").unwrap().simple.sig;
    bytes[..prologue.len()].copy_from_slice(&prologue);
    let fallback = Pattern::new(
        "EB 07 48 8D 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 B8 01 00 00 00 E8 | ?? ?? ?? ??",
    )
    .unwrap();
    bytes[64..64 + fallback.simple.len()].copy_from_slice(&fallback.simple.sig);
    relative(&mut bytes, 64 + fallback.custom_offset - 1, &[0xe8], 0x4000);
    let image = pe_image(bytes);
    let result = image
        .resolve(models::fname::FNameCtorWchar::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::fname::FNameCtorWchar::resolver())
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x1000);
}

#[test]
#[cfg(feature = "image-pe")]
fn fname_constructor_accepts_multiple_calls_to_the_same_target() {
    let mut bytes = vec![0x90; 256];
    let fallback = Pattern::new(
        "EB 07 48 8D 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 B8 01 00 00 00 E8 | ?? ?? ?? ??",
    )
    .unwrap();
    for offset in [0, 64] {
        bytes[offset..offset + fallback.simple.len()].copy_from_slice(&fallback.simple.sig);
        relative(
            &mut bytes,
            offset + fallback.custom_offset - 1,
            &[0xe8],
            0x4000,
        );
    }
    let image = pe_image(bytes);
    let result = image
        .resolve(models::fname::FNameCtorWchar::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::fname::FNameCtorWchar::resolver())
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x4000);
}

#[test]
#[cfg(feature = "image-elf")]
fn function_bind_elf_pipeline_matches_upstream() {
    let bytes = Pattern::new("41 56 53 50 49 89 fe 48 89 fb 66 0f 1f 44 00 00 e8 ?? ?? ?? ?? 48 8b 4b 10 48 63 50 38 3b 51 38 7e ?? 31 c0 48 8b 5b 20 48 85 db 75 ?? eb ?? 90 48 83 c0 30").unwrap().simple.sig;
    let image = image(bytes);
    let result = image
        .resolve(models::blueprint::UFunctionBind::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::blueprint_library::UFunctionBind::resolver())
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x1000);
}
