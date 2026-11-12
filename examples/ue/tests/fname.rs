use super::*;

#[cfg(feature = "image-pe")]
fn fname_ctor_bytes() -> Vec<u8> {
    let mut bytes = vec![0x90; 0x1000];
    for (offset, text) in [
        (0x800, "TGPUSkinVertexFactoryUnlimited\0"),
        (0x900, "MovementComponent0\0"),
    ] {
        let text = util::utf16(text);
        bytes[offset..offset + text.len()].copy_from_slice(&text);
    }
    bytes
}

#[cfg(feature = "image-pe")]
fn write_fname_ctor_reference(
    bytes: &mut [u8],
    offset: usize,
    layout: usize,
    string: u64,
    target: u64,
) {
    let signatures = [
        "48 8d 15 [ ?? ?? ?? ?? ] 4c 8d 05 ?? ?? ?? ?? 41 b1 01 e8 [ ?? ?? ?? ?? ]",
        "48 8d 15 [ ?? ?? ?? ?? ] 48 8d 0d ?? ?? ?? ?? e8 [ ?? ?? ?? ?? ]",
        "41 b8 01 00 00 00 48 8d 15 [ ?? ?? ?? ?? ] 48 8d 0d ?? ?? ?? ?? e9 [ ?? ?? ?? ?? ]",
    ];
    write_pattern(bytes, offset, signatures[layout], &[string, target]);
}

#[test]
#[cfg(feature = "image-pe")]
fn fname_ctor_capture_pipeline_preserves_prologue_and_inline_priority() {
    let prologue = "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 41 8B F8 33 C9 4C 8B DA 44 8B D1 4C 8B CA 48 85 D2 74 ?? 0F B7 02 66 85 C0";
    let inline =
        "EB 07 48 8D 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 B8 01 00 00 00 E8 [ ?? ?? ?? ?? ]";
    for (prologues, calls, expected) in [(1, 1, Some(0x1100)), (0, 2, Some(0x3000)), (2, 1, None)] {
        let mut bytes = fname_ctor_bytes();
        for index in 0..prologues {
            write_pattern(&mut bytes, 0x100 + index * 0x80, prologue, &[]);
        }
        for index in 0..calls {
            write_pattern(&mut bytes, 0x300 + index * 0x80, inline, &[0x3000]);
        }
        // A lower-priority thunk must not be decoded when an earlier heuristic matches.
        write_fname_ctor_reference(&mut bytes, 0x500, 0, 0x1800, 0x6000);
        let image = pe_image(bytes);
        let result = image.resolve(models::fname::FNameCtorWchar::resolver());
        let upstream =
            image.resolve(patternsleuth::resolvers::unreal::fname::FNameCtorWchar::resolver());

        assert_eq!(result.as_ref().ok().map(|value| value.0), expected);
        assert_eq!(
            result.ok().map(|value| value.0),
            upstream.ok().map(|value| value.0)
        );
    }
}

#[test]
#[cfg(feature = "image-pe")]
fn fname_ctor_capture_pipeline_matches_direct_jump_and_thunk_references() {
    for layout in 0..3 {
        let mut bytes = fname_ctor_bytes();
        write_fname_ctor_reference(&mut bytes, 0x100, layout, 0x1800, 0x1400);
        write_fname_ctor_reference(&mut bytes, 0x200, layout, 0x1900, 0x1400);
        relative(&mut bytes, 0x400, &[0xe8], 0x1600);
        let image = pe_image(bytes);
        let result = image
            .resolve(models::fname::FNameCtorWchar::resolver())
            .unwrap();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::fname::FNameCtorWchar::resolver())
            .unwrap();

        assert_eq!(result.0, upstream.0);
        if layout != 0 {
            assert_eq!(result.0, 0x1400);
        }
    }
}

#[test]
#[cfg(feature = "image-pe")]
fn fname_ctor_capture_pipeline_preserves_errors_and_lazy_uniqueness_limit() {
    let mut no_call = fname_ctor_bytes();
    write_fname_ctor_reference(&mut no_call, 0x100, 0, 0x1800, 0x1400);
    let mut conflicting = fname_ctor_bytes();
    write_fname_ctor_reference(&mut conflicting, 0x100, 1, 0x1800, 0x3000);
    write_fname_ctor_reference(&mut conflicting, 0x200, 2, 0x1800, 0x4000);
    let mut limited = fname_ctor_bytes();
    for index in 0..4 {
        write_fname_ctor_reference(
            &mut limited,
            0x100 + index * 0x40,
            1,
            0x1800,
            0x3000 + index as u64 * 0x100,
        );
    }
    write_fname_ctor_reference(&mut limited, 0x300, 0, 0x1900, 0x6000);
    for (bytes, expected) in [
        (fname_ctor_bytes(), "expected at least one value"),
        (no_call, "did not find CALL instruction"),
        (conflicting, "found 2 unique values"),
        (limited, "found >=4 unique values"),
    ] {
        let image = pe_image(bytes);
        let result = image
            .resolve(models::fname::FNameCtorWchar::resolver())
            .unwrap_err();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::fname::FNameCtorWchar::resolver())
            .unwrap_err();

        assert!(
            result.to_string().contains(expected),
            "{result}; expected {expected}"
        );
        assert_eq!(result.to_string(), upstream.to_string());
    }
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

fn fname_pool_bytes(property_strings: bool) -> Vec<u8> {
    let mut bytes = vec![0x90; 0x800];
    if property_strings {
        for (index, text) in [
            "\0ByteProperty\0",
            "\0IntProperty\0",
            "\0BoolProperty\0",
            "\0FloatProperty\0",
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 0x400 + index * 0x40;
            bytes[offset..offset + text.len()].copy_from_slice(text.as_bytes());
            relative(
                &mut bytes,
                0x10 + index * 7,
                &[0x48, 0x8d, 0x0d],
                0x1001 + offset as u64,
            );
        }
    } else {
        write_pattern(&mut bytes, 0x10, "48 89 41 08 41 b8 00 00 01 00", &[]);
        relative(&mut bytes, 0x50, &[0xe8], 0x1000);
    }
    bytes
}

fn write_fname_pool_match(
    bytes: &mut [u8],
    offset: usize,
    pool: u64,
    constructor: u64,
    extra: bool,
) {
    let signature = if extra {
        "48 8d 0d [ ?? ?? ?? ?? ] e8 [ ?? ?? ?? ?? ] 90 90 90 c6 05 ?? ?? ?? ?? 01"
    } else {
        "48 8d 0d [ ?? ?? ?? ?? ] e8 [ ?? ?? ?? ?? ] c6 05 ?? ?? ?? ?? 01"
    };
    write_pattern(bytes, offset, signature, &[pool, constructor]);
}

#[test]
fn fname_pool_capture_pipeline_matches_bodies_callers_and_property_intersections() {
    for (strings, constructor) in [(false, 0x1000), (false, 0x1040), (true, 0x1000)] {
        for extra in [false, true] {
            let mut bytes = fname_pool_bytes(strings);
            if extra && !strings {
                bytes[0x50] = 0xe9;
            }
            write_fname_pool_match(&mut bytes, 0x100, 0x4000, constructor, extra);
            write_fname_pool_match(&mut bytes, 0x180, 0x4000, constructor, !extra);
            write_fname_pool_match(&mut bytes, 0x200, 0x5000, 0x2000, extra);
            let image = two_function_image(bytes);
            let result = image.resolve(models::fname::FNamePool::resolver()).unwrap();
            let upstream = image
                .resolve(patternsleuth::resolvers::unreal::fname::FNamePool::resolver())
                .unwrap();

            assert_eq!(result.0, 0x4000);
            assert_eq!(result.0, upstream.0);
        }
    }
}

#[test]
fn fname_pool_capture_pipeline_preserves_modern_priority_and_legacy_fallback() {
    for (constructor, second_pool, expected) in [
        (0x1000, 0x4000, 0x4000),
        (0x1000, 0x5000, 0x6000),
        (0x2000, 0x4000, 0x6000),
    ] {
        let mut bytes = fname_pool_bytes(false);
        write_fname_pool_match(&mut bytes, 0x100, 0x4000, constructor, false);
        write_fname_pool_match(&mut bytes, 0x180, second_pool, constructor, true);
        write_pattern(
            &mut bytes,
            0x300,
            "48 83 EC 28 48 8B 05 [ ?? ?? ?? ?? ] 48 85 C0 75 01 B9 08 04 00 00",
            &[0x6000],
        );
        let image = two_function_image(bytes);
        let result = image.resolve(models::fname::FNamePool::resolver()).unwrap();
        let upstream = image
            .resolve(patternsleuth::resolvers::unreal::fname::FNamePool::resolver())
            .unwrap();

        assert_eq!(result.0, expected);
        assert_eq!(result.0, upstream.0);
    }
}

#[test]
fn fname_pool_capture_pipeline_requires_every_property_reference_in_one_function() {
    for split in [false, true] {
        let mut bytes = fname_pool_bytes(true);
        if split {
            // Move the fourth reference into a different function.
            bytes[0x25..0x2c].fill(0x90);
            relative(&mut bytes, 0x50, &[0x48, 0x8d, 0x0d], 0x14c1);
        } else {
            bytes[0x10..0x17].fill(0x90);
        }
        write_fname_pool_match(&mut bytes, 0x100, 0x4000, 0x1000, false);
        let image = two_function_image(bytes);
        let result = image.resolve(models::fname::FNamePool::resolver());
        let upstream =
            image.resolve(patternsleuth::resolvers::unreal::fname::FNamePool::resolver());

        assert!(result.is_err());
        assert!(upstream.is_err());
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
