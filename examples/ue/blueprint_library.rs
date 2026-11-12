//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/blueprint_library.rs>

use binary_bloodhound::{BinaryMatcher, Matcher};
use futures::join;

use super::util;
#[cfg(feature = "image-pe")]
use patternsleuth::resolvers::ensure_one;
use patternsleuth::scanner::Pattern;

use patternsleuth::{
    Addressable,
    resolvers::{Context, impl_resolver, impl_resolver_singleton},
};

pub use super::models::blueprint::BlueprintLibraryInit;

impl_resolver!(all, BlueprintLibraryInit, |ctx| async {
    let mem = &ctx.image().memory;

    let class_str = BinaryMatcher::pattern(util::utf16_pattern("UKismetStringTableLibrary\0"))
        .resolve(ctx)
        .await?;

    let pattern_dyn_init_class = |s: u64| {
        format!(
            "41 b9 ?? ?? ?? ?? 48 8d 15 X0x{s:x} 41 b8 28 00 00 00 48 8d 0d [ ?? ?? ?? ?? ] e9 [ ?? ?? ?? ?? ]"
        )
    };
    let pattern_dyn_init_object = |s: u64| {
        format!(
            "
                48 83 ec 48
                33 c0
                4c 8d 0d ?? ?? ?? ??
                48 89 44 24 30
                4c 8d 05 X0x{s:x}
                48 89 44 24 28
                48 8d 15 [ ?? ?? ?? ?? ]
                48 8d 0d [ ?? ?? ?? ?? ]
                88 44 24 20
                e8 [ ?? ?? ?? ?? ]
                48 83 c4 48
                c3
            "
        )
    };

    let construct_uclass_pattern = Pattern::new(
        "
            48 83 ec 28
            48 8b 05 ?? ?? ?? ??
            48 85 c0
            75 1a
            48 8d 15 ?? ?? ?? ??
            48 8d 0d ?? ?? ?? ??
            e8 [ ?? ?? ?? ?? ]
            48 8b 05 ?? ?? ?? ??
            48 83 c4 28
            c3
        ",
    )
    .unwrap();

    let init_class = Matcher::from_nodes(&class_str)
        .try_flat_map(|node| BinaryMatcher::capture_patterns([pattern_dyn_init_class(*node.value)]))
        .try_map(|node| node.captures[1].rip4())
        .ensure_one();
    let init_object = Matcher::from_nodes(&class_str)
        .try_flat_map(|node| {
            BinaryMatcher::capture_patterns([pattern_dyn_init_object(*node.value)])
        })
        .try_map(|node| {
            let caps = &node.captures;
            Ok((caps[0].rip4()?, caps[1].rip4()?, caps[2].rip4()?))
        })
        .ensure_one();
    let (init_class, init_object) = join!(init_class.resolve(ctx), init_object.resolve(ctx));

    let uclass_compiled_in_defer = *init_class?.value;
    let (get_private_static_class_wrapper, construct_uclass_wrapper, uobject_compiled_in_defer) =
        *init_object?.value;

    let construct_uclass = mem
        .captures(&construct_uclass_pattern, construct_uclass_wrapper)?
        .context("Construct_UClass pattern did not match")?[0]
        .rip();

    let get_private_static_class_pattern = Pattern::new(
        "
            4c 8b dc
            48 81 ec 88 00 00 00
            48 8b 05 ?? ?? ?? ??
            48 85 c0
            0f 85 90 00 00 00
            33 c9
            48 8d 05 [ ?? ?? ?? ?? ]
            49 89 4b f0
            4c 8d 0d ?? ?? ?? ??
            88 4c 24 70
            4c 8d 05 ?? ?? ?? ??
            49 89 43 e0
            48 8d 15 ?? ?? ?? ??
            48 8d 05 [ ?? ?? ?? ?? ]
            49 89 43 d8
            48 8d 05 ?? ?? ?? ??
            49 89 43 d0
            48 8d 05 ?? ?? ?? ??
            49 89 43 c8
            48 8d 05 ?? ?? ?? ??
            49 89 43 c0
            48 8d 05 ?? ?? ?? ??
            49 89 43 b8
            49 89 4b b0
            48 8d 0d ?? ?? ?? ??
            c7 44 24 30 ?? ?? ?? ??
            c7 44 24 28 ?? ?? ?? ??
            c7 44 24 20 ?? ?? ?? ??
            e8 [ ?? ?? ?? ?? ]
            48 8b 05 ?? ?? ?? ??
            48 81 c4 88 00 00 00
            c3
    ",
    )
    .unwrap();

    let (
        uobject_static_class,
        ublueprint_function_library_static_class,
        get_private_static_class_body,
    ) = {
        let captures = mem
            .captures(
                &get_private_static_class_pattern,
                get_private_static_class_wrapper,
            )?
            .context("Construct_UClass pattern did not match")?;

        (captures[0].rip(), captures[1].rip(), captures[2].rip())
    };

    Ok(Self {
        uclass_compiled_in_defer,
        uobject_compiled_in_defer,
        construct_uclass,
        get_private_static_class_body,
        uobject_static_class,
        ublueprint_function_library_static_class,
    })
});

/// UFunction::Bind
pub use super::models::blueprint::UFunctionBind;
impl_resolver_singleton!(collect, UFunctionBind);
impl_resolver_singleton!(PEImage, UFunctionBind, |ctx| async {
    let string = BinaryMatcher::pattern(util::utf16_pattern(
        "Failed to bind native function %s.%s\0",
    ))
    .references()
    .root_functions()
    .addresses();
    let pattern = BinaryMatcher::patterns([
        "48 89 5C 24 ?? 57 48 83 EC 20 33 D2 48 8B F9 48 8B D9 48 85 C9 74 3D 48 85 D2 75 38 48 85 DB 74 28 E8",
    ])?;
    let (string, pattern) = join!(string.resolve(ctx), pattern.resolve(ctx));

    Ok(Self(ensure_one(
        string?
            .into_iter()
            .map(|node| *node.value)
            .chain(pattern?.into_iter().map(|node| *node.value)),
    )?))
});

impl_resolver_singleton!(ElfImage, UFunctionBind, |ctx| async {
    // maybe find symbol of vtable?
    BinaryMatcher::patterns([
        "41 56 53 50 49 89 fe 48 89 fb 66 0f 1f 44 00 00 e8 ?? ?? ?? ?? 48 8b 4b 10 48 63 50 38 3b 51 38 7e ?? 31 c0 48 8b 5b 20 48 85 db 75 ?? eb ?? 90 48 83 c0 30",
    ])?
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});
