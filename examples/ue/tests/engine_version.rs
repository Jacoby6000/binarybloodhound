use super::*;

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
