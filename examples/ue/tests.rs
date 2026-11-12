use super::*;
use object::SectionKind;
use patternsleuth::{
    Memory, NamedMemorySection,
    image::{Image, ImageType},
    scanner::Pattern,
};

#[cfg(feature = "image-pe")]
mod aes;
mod blueprint;
mod engine;
mod engine_version;
mod fname;
mod ftext;
mod kismet;
mod objects;
mod post_load;
mod scan;

#[test]
fn factory_list_has_all_resolvers_without_duplicate_names() {
    let names: std::collections::HashSet<_> =
        factories().iter().map(|factory| factory().name).collect();

    assert_eq!(names.len(), 58);
}

#[cfg(any(feature = "image-pe", feature = "image-elf"))]
pub(super) fn image(mut bytes: Vec<u8>) -> Image<'static> {
    bytes.resize(bytes.len().max(512), 0x90);
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

fn write_pattern(bytes: &mut [u8], offset: usize, signature: &str, targets: &[u64]) {
    let pattern = Pattern::new(signature).unwrap();
    let end = offset + pattern.simple.sig.len();
    bytes[offset..end].copy_from_slice(&pattern.simple.sig);
    assert_eq!(pattern.captures.len(), targets.len());
    for (range, target) in pattern.captures.iter().zip(targets) {
        let at = offset + range.start;
        let displacement = i32::try_from(*target as i64 - (0x1000 + at + 4) as i64).unwrap();
        bytes[at..at + 4].copy_from_slice(&displacement.to_le_bytes());
    }
}

fn relative(bytes: &mut [u8], offset: usize, opcode: &[u8], target: u64) {
    bytes[offset..offset + opcode.len()].copy_from_slice(opcode);
    let next = 0x1000 + (offset + opcode.len() + 4) as u64;
    let displacement = i32::try_from(i128::from(target) - i128::from(next)).unwrap();
    bytes[offset + opcode.len()..offset + opcode.len() + 4]
        .copy_from_slice(&displacement.to_le_bytes());
}

fn two_function_image(bytes: Vec<u8>) -> Image<'static> {
    #[cfg(feature = "image-pe")]
    let image = pe_image(bytes);
    #[cfg(all(feature = "image-elf", not(feature = "image-pe")))]
    let image = elf_two_function_image(bytes);
    image
}

#[cfg(feature = "image-elf")]
fn elf_two_function_image(bytes: Vec<u8>) -> Image<'static> {
    let image = image(bytes);
    Image::from_memory(
        0x1000,
        image.memory,
        ImageType::ElfImage(patternsleuth::image::elf::ElfImage {
            functions: Some(vec![0x1000..0x1040, 0x1040..0x1080]),
        }),
    )
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
    #[cfg(feature = "image-elf")]
    {
        elf_two_function_image(bytes)
    }
    #[cfg(all(feature = "image-pe", not(feature = "image-elf")))]
    pe_image(bytes)
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
