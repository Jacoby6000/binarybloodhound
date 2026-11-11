use super::*;
use patternsleuth::{
    resolvers::{ResolveError, Result},
    scanner::Pattern,
};

const BASE: u64 = 0x1_4000_0000;
const TEXT: u64 = BASE + 0x1000;
const TARGET: u64 = BASE + 0x4000;

mod fixtures;

#[cfg(feature = "image-pe")]
mod pe {
    use super::fixtures::pe as construct_image;
    include!("tests/shared.rs");

    #[test]
    fn xrefs_propagate_unwind_memory_errors() {
        let mut text = vec![0x90; 256];
        relative(&mut text, 8, &[0xe8], TARGET);
        let image = image(text).without_section(".xdata");

        assert!(run(&image, xrefs(TARGET)).is_err());
    }

    #[test]
    fn function_traversal_propagates_unwind_memory_errors() {
        let image = call_graph().without_section(".xdata");
        for operation in 0..3 {
            let matcher = BinaryMatcher::address(SHARED_CALLER);
            let result = match operation {
                0 => run(&image, matcher.root_functions()),
                1 => run(&image, matcher.callees()),
                _ => run(&image, matcher.call_sites()),
            };
            let error = result.unwrap_err();

            assert_eq!(
                error.to_string(),
                patternsleuth::MemoryAccessError::MemoryOutOfBoundsError.to_string()
            );
        }
    }

    #[test]
    fn root_functions_propagate_missing_function_table_memory() {
        let image = scan_image().without_section(".pdata");
        let error = run(&image, BinaryMatcher::address(TEXT).root_functions()).unwrap_err();

        assert_eq!(
            error,
            ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
        );
    }

    #[test]
    fn root_functions_reject_invalid_function_table_ranges() {
        for (start, end) in [
            (BASE + 0x2000, BASE + 0x2001),
            (BASE + 0x2001, BASE + 0x2000),
        ] {
            let mut image = scan_image();
            image.image_type =
                patternsleuth::image::ImageType::PEImage(patternsleuth::image::pe::PEImage {
                    exception_directory_range: start..end,
                    exception_children_cache: Default::default(),
                });
            let error = run(&image, BinaryMatcher::address(TEXT).root_functions()).unwrap_err();

            assert_eq!(
                error,
                ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
            );
        }
    }

    #[test]
    fn root_functions_reject_function_address_overflow() {
        let mut image = scan_image();
        image.base_address = u64::MAX;
        let error = run(&image, BinaryMatcher::address(TEXT).root_functions()).unwrap_err();

        assert_eq!(
            error,
            ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
        );
    }
}

#[cfg(feature = "image-elf")]
mod elf {
    use super::fixtures::elf as construct_image;
    include!("tests/shared.rs");
}
