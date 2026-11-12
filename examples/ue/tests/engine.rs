use super::*;

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

#[test]
#[cfg(feature = "image-pe")]
fn world_tick_tagged_pipeline_preserves_anchor_identity_and_ranking() {
    let specific = "UWorld_Tick\0";
    let other_specific = "World Tick Time\0";
    let generic = "ConnectionFailed\0";
    let cases = [
        (vec![(specific, 0x10)], Some(0x1000)),
        (
            vec![
                (specific, 0x10),
                (generic, 0x40),
                ("Media\0", 0x48),
                ("Your connection to the host has been lost.\0", 0x50),
            ],
            Some(0x1000),
        ),
        (
            vec![(specific, 0x10), (other_specific, 0x18), (specific, 0x40)],
            Some(0x1000),
        ),
        (
            vec![(specific, 0x10), (specific, 0x18), (specific, 0x40)],
            None,
        ),
        (vec![(generic, 0x10), ("Media\0", 0x18)], None),
        (vec![(specific, 0x100)], None),
        (vec![], None),
    ];
    for (anchors, expected) in cases {
        let mut bytes = vec![0x90; 0x1000];
        for (index, (text, site)) in anchors.into_iter().enumerate() {
            let offset = 0x200 + index * 0x80;
            let text = util::utf16(text);
            bytes[offset..offset + text.len()].copy_from_slice(&text);
            relative(
                &mut bytes,
                site,
                &[0x48, 0x8d, 0x0d],
                0x1000 + offset as u64,
            );
        }
        let image = pe_image(bytes);
        let result = image.resolve(models::engine::UWorldTick::resolver());
        let upstream =
            image.resolve(patternsleuth::resolvers::unreal::game_loop::UWorldTick::resolver());

        assert_eq!(result.as_ref().ok().map(|value| value.0), expected);
        assert_eq!(
            result.as_ref().ok().map(|value| value.0),
            upstream.as_ref().ok().map(|value| value.0)
        );
        if let (Err(result), Err(upstream)) = (result, upstream) {
            assert_eq!(result.to_string(), upstream.to_string());
        }
    }
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
