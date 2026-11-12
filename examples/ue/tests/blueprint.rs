use super::*;

fn blueprint_init_bytes(second_class_target: u64) -> Vec<u8> {
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
