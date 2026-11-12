use super::*;

fn post_load_bytes(text: &str) -> Vec<u8> {
    let mut bytes = vec![0x90; 0x1000];
    let text = util::utf16(text);
    bytes[0x800..0x800 + text.len()].copy_from_slice(&text);
    bytes
}

fn indirect_post_load_bytes(text: &str, layout: usize) -> Vec<u8> {
    let mut bytes = post_load_bytes(text);
    let (signature, targets) = match layout {
        0 => (
            "48 8b cb e8 [ ?? ?? ?? ?? ] 48 8d 15 [ ?? ?? ?? ?? ] 48 89 9f 90 00 00 00 48 89 97 98 00 00 00 c3",
            vec![0x3000, 0x1800],
        ),
        1 => (
            "48 8b cb e8 [ ?? ?? ?? ?? ] 48 89 9f 90 00 00 00 48 8d 15 [ ?? ?? ?? ?? ] 48 89 97 98 00 00 00 c3",
            vec![0x3000, 0x1800],
        ),
        2 => (
            "48 8d 35 [ ?? ?? ?? ?? ] 90 48 8b cb e8 [ ?? ?? ?? ?? ] 48 89 9f 90 00 00 00 48 89 b7 98 00 00 00 c3",
            vec![0x1800, 0x3000],
        ),
        3 => (
            "48 8d 35 [ ?? ?? ?? ?? ] 90 48 8b cb e8 [ ?? ?? ?? ?? ] 48 89 b7 98 00 00 00 48 89 9f 90 00 00 00 c3",
            vec![0x1800, 0x3000],
        ),
        4 => (
            "48 8b cb e8 [ ?? ?? ?? ?? ] 90 48 8b cb e8 [ ?? ?? ?? ?? ] 48 8d 15 [ ?? ?? ?? ?? ] 48 89 9f 90 00 00 00 48 89 97 98 00 00 00 c3",
            vec![0x3000, 0x4000, 0x1800],
        ),
        _ => unreachable!(),
    };
    write_pattern(&mut bytes, 0, signature, &targets);
    bytes
}

#[test]
fn post_load_tagged_pipeline_matches_indirect_assignment_layouts() {
    for text in ["postloading\0", "postloading_async\0"] {
        for layout in 0..5 {
            let image = two_function_image(indirect_post_load_bytes(text, layout));
            let result = image
                .resolve(models::objects::UObjectConditionalPostLoad::resolver())
                .unwrap_or_else(|error| panic!("{text:?} layout {layout}: {error}"));
            let upstream = image.resolve(patternsleuth::resolvers::unreal::uobject_conditional_post_load::UObjectConditionalPostLoad::resolver()).unwrap();

            assert_eq!(result.0, if layout == 4 { 0x4000 } else { 0x3000 });
            assert_eq!(result.0, upstream.0);
        }
    }
}

#[test]
fn post_load_tagged_pipeline_matches_direct_development_references() {
    let text = "%s failed to route PostLoad.  Please call Super::PostLoad() in your <className>::PostLoad() function.\0";
    for opcode in [[0x48, 0x8d, 0x0d], [0x4c, 0x8d, 0x05]] {
        let mut bytes = post_load_bytes(text);
        relative(&mut bytes, 0, &opcode, 0x1800);
        relative(&mut bytes, 0x20, &opcode, 0x1800);
        relative(&mut bytes, 0x100, &opcode, 0x1800); // No containing function.
        let image = two_function_image(bytes);
        let result = image
            .resolve(models::objects::UObjectConditionalPostLoad::resolver())
            .unwrap();
        let upstream = image.resolve(patternsleuth::resolvers::unreal::uobject_conditional_post_load::UObjectConditionalPostLoad::resolver()).unwrap();

        assert_eq!(result.0, 0x1000);
        assert_eq!(result.0, upstream.0);
    }
}

#[test]
fn post_load_tagged_pipeline_preserves_missing_tail_and_ambiguity_errors() {
    let mut missing_tail = indirect_post_load_bytes("postloading\0", 0);
    missing_tail[22..29].fill(0x90);
    let mut volatile_object = indirect_post_load_bytes("postloading\0", 0);
    volatile_object[2] = 0xc8; // mov rcx, rax: object source must be nonvolatile.
    let mut ambiguous = post_load_bytes(
        "%s failed to route PostLoad.  Please call Super::PostLoad() in your <className>::PostLoad() function.\0",
    );
    relative(&mut ambiguous, 0, &[0x48, 0x8d, 0x0d], 0x1800);
    relative(&mut ambiguous, 0x40, &[0x48, 0x8d, 0x0d], 0x1800);
    for bytes in [vec![], missing_tail, volatile_object, ambiguous] {
        let image = two_function_image(bytes);
        let result = image
            .resolve(models::objects::UObjectConditionalPostLoad::resolver())
            .unwrap_err();
        let upstream = image.resolve(patternsleuth::resolvers::unreal::uobject_conditional_post_load::UObjectConditionalPostLoad::resolver()).unwrap_err();

        assert_eq!(result.to_string(), upstream.to_string());
    }
}
