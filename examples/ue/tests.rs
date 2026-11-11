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
fn image(mut bytes: Vec<u8>) -> Image<'static> {
    bytes.resize(512, 0x90);
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
