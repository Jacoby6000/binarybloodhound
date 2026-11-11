//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/gengine.rs>

use patternsleuth::resolvers::impl_resolver_singleton;

pub use super::models::engine::GEngine;
impl_resolver_singleton!(collect, GEngine);
impl_resolver_singleton!(PEImage, GEngine, |ctx| async {
    use super::util;
    use binary_bloodhound::{BinaryMatcher, Control};
    use iced_x86::Register;

    BinaryMatcher::pattern(util::utf16_pattern("rhi.DumpMemory\0"))
        .references()
        .root_functions()
        .walk_disassembly(
            |root| (root.value.start, root.parent().value.0, None),
            |(start, reference_addr, rcx), inst| {
                let ip = inst.ip();
                let op0_reg = inst.op0_register();

                if !(start..=reference_addr).contains(&ip) {
                    return Ok(Control::Break);
                }
                match op0_reg {
                    Register::R8 if ip == reference_addr => {
                        Ok(rcx.map_or(Control::Break, Control::Return))
                    }
                    Register::RCX if inst.is_ip_rel_memory_operand() => Ok(Control::Continue((
                        start,
                        reference_addr,
                        Some(inst.ip_rel_memory_address()),
                    ))),
                    _ => Ok(Control::Continue((start, reference_addr, rcx))),
                }
            },
        )
        .ensure_one()
        .resolve(ctx)
        .await
        .map(|node| Self(*node.value))
});
impl_resolver_singleton!(ElfImage, GEngine, |_ctx| async {
    patternsleuth::resolvers::bail_out!("ElfImage unimplemented");
});
