//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/dispatch_begin_play.rs>

use binary_bloodhound::BinaryMatcher;

use patternsleuth::resolvers::impl_resolver_singleton;

/// void AActor::DispatchBeginPlay(...)
pub use super::models::actor::AActorDispatchBeginPlay;
impl_resolver_singleton!(all, AActorDispatchBeginPlay, |ctx| async {
    let patterns = [
        "48 8B 0B B2 01 E8 | ?? ?? ?? ?? 48 8D 5B 08 48",
        "33 D2 48 8B CF E8 | ?? ?? ?? ?? EB 7A 8B 47 0C",
        "84 C0 75 0A B2 01 48 8B ?? E8 | ?? ?? ?? ?? 8B 83 ?? 03 00 00 FF C0 89 83 ?? 03 00 00",
        "48 8B C8 E8 ?? ?? ?? ?? 84 C0 74 08 48 8B CB E8 | ?? ?? ?? ?? B2 01 48 8B CB 48 83 C4 ?? 5B E9",
        "00 00 00 4C 89 BC 24 A0 00 00 00 0F 1F 44 00 00 48 8B ?? E8 | ?? ?? ?? ?? ?? ?? ?? ?? 8B ?? ?? 44 8B ?? CF 4C 8B 6D B7 41 FF",
        "8B FD 66 90 48 8B 0B E8 | ?? ?? ?? ?? 48 8D 5B 08 48",
    ];

    BinaryMatcher::patterns(patterns)?
        .rip4()
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});
