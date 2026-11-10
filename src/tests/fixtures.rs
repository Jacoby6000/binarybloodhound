use super::{BASE, TEXT};
use object::SectionKind;
use patternsleuth::{
    Memory, NamedMemorySection,
    image::{Image, ImageType},
};

fn image(text: Vec<u8>, image_type: ImageType) -> Image<'static> {
    Image::from_memory(
        BASE,
        Memory::from_sections(vec![NamedMemorySection::new(
            ".text".into(),
            TEXT,
            SectionKind::Text,
            text,
        )]),
        image_type,
    )
}

#[cfg(feature = "image-pe")]
pub(super) fn pe(text: Vec<u8>, functions: u32) -> Image<'static> {
    let image = image(
        text,
        ImageType::PEImage(patternsleuth::image::pe::PEImage {
            exception_directory_range: BASE + 0x2000..BASE + 0x2000 + u64::from(functions) * 12,
            exception_children_cache: Default::default(),
        }),
    );
    let pdata: Vec<u8> = (0..functions)
        .flat_map(|i| [0x1000 + i * 0x40, 0x1040 + i * 0x40, 0x3000 + i * 4])
        .flat_map(u32::to_le_bytes)
        .collect();
    let image = image.with_section(NamedMemorySection::new(
        ".pdata".into(),
        BASE + 0x2000,
        SectionKind::ReadOnlyData,
        pdata,
    ));
    image.with_section(NamedMemorySection::new(
        ".xdata".into(),
        BASE + 0x3000,
        SectionKind::ReadOnlyData,
        [1, 0, 0, 0].repeat(functions as usize),
    ))
}

#[cfg(feature = "image-elf")]
pub(super) fn elf(text: Vec<u8>, functions: u32) -> Image<'static> {
    image(
        text,
        ImageType::ElfImage(patternsleuth::image::elf::ElfImage {
            functions: Some(
                (0..functions)
                    .map(|i| {
                        let start = TEXT + u64::from(i) * 0x40;
                        start..start + 0x40
                    })
                    .collect(),
            ),
        }),
    )
}
