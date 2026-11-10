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
        .resolve(fuobject_hash_tables::FUObjectHashTablesGet::resolver())
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
        .resolve(game_loop::UGameEngineTick::resolver())
        .unwrap();
    let upstream = image
        .resolve(patternsleuth::resolvers::unreal::game_loop::UGameEngineTick::resolver())
        .unwrap();

    assert_eq!(result.0, upstream.0);
    assert_eq!(result.0, 0x1000);
}
