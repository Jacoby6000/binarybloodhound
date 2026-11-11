//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/mod.rs>
// Ported from patternsleuth's Unreal resolvers (MIT OR Apache-2.0).
pub mod aes;
pub mod blueprint_library;
pub mod dispatch_begin_play;
pub mod engine_version;
pub mod fname;
pub mod ftext;
pub mod fuobject_hash_tables;
pub mod game_loop;
pub mod gengine;
pub mod gmalloc;
pub mod guobject_array;
pub mod kismet;
pub mod models;
pub mod pak;
pub mod save_game;
mod scan;
pub mod static_construct_object;
pub mod static_find_object;
pub mod static_load_object;
pub mod uobject_conditional_post_load;
pub mod util;

#[cfg(test)]
mod tests;

use binary_bloodhound::BinaryMatcher;
use patternsleuth::resolvers::{DynResolverFactory, impl_resolver_singleton};

pub use models::engine::ConsoleManagerSingleton;
impl_resolver_singleton!(all, ConsoleManagerSingleton, |ctx| async {
    let strings = BinaryMatcher::patterns([
        util::utf16_pattern("r.DumpingMovie"),
        util::utf16_pattern("vr.pixeldensity"),
    ])?
    .resolve(ctx)
    .await?;
    let patterns = strings
        .into_iter()
        .map(|address| format!("48 8d 15 X0x{:x}", *address.value));
    let address = BinaryMatcher::patterns(patterns)?
        .root_functions()
        .addresses()
        .ensure_one()
        .resolve(ctx)
        .await?;
    Ok(Self(*address.value))
});

pub use models::objects::UObjectBaseUtilityGetPathName;
impl_resolver_singleton!(all, UObjectBaseUtilityGetPathName, |ctx| async {
    let address = BinaryMatcher::patterns([
        "40 53 48 81 EC 50 02 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? 48 8D 44 24",
    ])?.ensure_one().resolve(ctx).await?;
    Ok(Self(*address.value))
});

// Select these factories explicitly: upstream resolvers share this process's inventory.
pub fn factories() -> Vec<fn() -> &'static DynResolverFactory> {
    vec![
        aes::AESKeys::dyn_resolver,
        blueprint_library::BlueprintLibraryInit::dyn_resolver,
        blueprint_library::UFunctionBind::dyn_resolver,
        dispatch_begin_play::AActorDispatchBeginPlay::dyn_resolver,
        engine_version::EngineVersion::dyn_resolver,
        engine_version::EngineVersionStrings::dyn_resolver,
        engine_version::CustomVersionRegistry::dyn_resolver,
        engine_version::StaticCustomVersions::dyn_resolver,
        engine_version::BuildChangeList::dyn_resolver,
        engine_version::InternalProjectName::dyn_resolver,
        engine_version::EngineVersionFingerprint::dyn_resolver,
        engine_version::BuildConfiguration::dyn_resolver,
        engine_version::Stats::dyn_resolver,
        fname::FNameCtorWchar::dyn_resolver,
        fname::FNameToString::dyn_resolver,
        fname::FNameToStringVoid::dyn_resolver,
        fname::FNameToStringFString::dyn_resolver,
        fname::FNamePool::dyn_resolver,
        fname::StaticFNameConst::dyn_resolver,
        ftext::FTextFString::dyn_resolver,
        fuobject_hash_tables::FUObjectHashTablesGet::dyn_resolver,
        game_loop::Main::dyn_resolver,
        game_loop::FEngineLoopTick::dyn_resolver,
        game_loop::UGameEngineTick::dyn_resolver,
        game_loop::FEngineLoopInit::dyn_resolver,
        game_loop::UWorldTick::dyn_resolver,
        gengine::GEngine::dyn_resolver,
        gmalloc::GMalloc::dyn_resolver,
        gmalloc::GMallocPatterns::dyn_resolver,
        gmalloc::GMallocString::dyn_resolver,
        guobject_array::GUObjectArray::dyn_resolver,
        guobject_array::FUObjectArrayAllocateUObjectIndex::dyn_resolver,
        guobject_array::FUObjectArrayFreeUObjectIndex::dyn_resolver,
        guobject_array::UObjectBaseShutdown::dyn_resolver,
        kismet::UObjectSkipFunction::dyn_resolver,
        kismet::GNatives::dyn_resolver,
        kismet::GNativesPatterns::dyn_resolver,
        kismet::GNativesViaSkipFunction::dyn_resolver,
        kismet::GNativesViaFFrameStep::dyn_resolver,
        kismet::FFrameStep::dyn_resolver,
        kismet::FFrameStepExplicitProperty::dyn_resolver,
        kismet::FFrameStepViaExec::dyn_resolver,
        ConsoleManagerSingleton::dyn_resolver,
        UObjectBaseUtilityGetPathName::dyn_resolver,
        pak::FPakPlatformFileInitialize::dyn_resolver,
        save_game::UGameplayStaticsSaveGameToMemory::dyn_resolver,
        save_game::UGameplayStaticsSaveGameToSlot::dyn_resolver,
        save_game::UGameplayStaticsLoadGameFromMemory::dyn_resolver,
        save_game::UGameplayStaticsLoadGameFromSlot::dyn_resolver,
        save_game::UGameplayStaticsDoesSaveGameExist::dyn_resolver,
        static_construct_object::StaticConstructObjectInternal::dyn_resolver,
        static_construct_object::StaticConstructObjectInternalPatterns::dyn_resolver,
        static_construct_object::StaticConstructObjectInternalString::dyn_resolver,
        static_find_object::StaticFindObjectFast::dyn_resolver,
        static_load_object::StaticLoadObject::dyn_resolver,
        static_load_object::StaticLoadObjectPatterns::dyn_resolver,
        static_load_object::StaticLoadObjectString::dyn_resolver,
        uobject_conditional_post_load::UObjectConditionalPostLoad::dyn_resolver,
    ]
}
