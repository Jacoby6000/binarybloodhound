//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/gengine.rs>

use patternsleuth::resolvers::impl_resolver_singleton;

pub use super::models::engine::GEngine;
impl_resolver_singleton!(collect, GEngine);
impl_resolver_singleton!(PEImage, GEngine, |ctx| async {
    use super::util;
    use binary_bloodhound::BinaryMatcher;
    use iced_x86::Register;
    use patternsleuth::disassemble::{Control, disassemble};

    BinaryMatcher::pattern(util::utf16_pattern("rhi.DumpMemory\0"))
        .references()
        .flat_map(|reference| {
            BinaryMatcher::candidates([reference.0])
                .root_functions()
                .with_context()
                .filter_modify(move |(ctx, function)| {
                    let mut is_match = false;
                    let mut rcx = None;

                    disassemble(ctx.image(), function.start, |inst| {
                        let cur = inst.ip();
                        if !(function.start..=reference.0).contains(&cur) {
                            return Ok(Control::Break);
                        }
                        if reference.0 == cur && inst.op0_register() == Register::R8 {
                            is_match = true;
                            return Ok(Control::Break);
                        }
                        if inst.op0_register() == Register::RCX && inst.is_ip_rel_memory_operand() {
                            rcx = Some(inst.ip_rel_memory_address());
                        }
                        Ok(Control::Continue)
                    })?;

                    Ok(is_match.then_some(rcx).flatten())
                })
        })
        .ensure_one()
        .map(Self)
        .resolve(ctx)
        .await
});
impl_resolver_singleton!(ElfImage, GEngine, |_ctx| async {
    patternsleuth::resolvers::bail_out!("ElfImage unimplemented");
});
