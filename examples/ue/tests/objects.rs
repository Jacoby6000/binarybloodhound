use super::*;

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
