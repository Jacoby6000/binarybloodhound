//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/dispatch_begin_play.rs>

/// AActor::DispatchBeginPlay.
#[derive(Debug, PartialEq)]
#[cfg_attr(
    feature = "serde-resolvers",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct AActorDispatchBeginPlay(pub u64);
