use super::*;

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
