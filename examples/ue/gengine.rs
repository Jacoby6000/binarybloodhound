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
        .walk_disassembly(
            |reference| (reference.0, None, None),
            |(reference_addr, start, rcx), inst| {
                let ip = inst.ip();
                let op0_reg = inst.op0_register();
                let start = start.unwrap_or(ip);

                if !(start..=reference_addr).contains(&ip) {
                    return Ok(Control::Break);
                }
                if ip == reference_addr && op0_reg == Register::R8 {
                    return Ok(rcx.map_or(Control::Break, Control::Return));
                }
                match (op0_reg, inst.is_ip_rel_memory_operand()) {
                    (Register::RCX, true) => Ok(Control::Continue((
                        reference_addr,
                        Some(start),
                        Some(inst.ip_rel_memory_address()),
                    ))),
                    _ => Ok(Control::Continue((reference_addr, Some(start), rcx))),
                }
            },
        )
        .ensure_one()
        .map(Self)
        .resolve(ctx)
        .await
});
impl_resolver_singleton!(ElfImage, GEngine, |_ctx| async {
    patternsleuth::resolvers::bail_out!("ElfImage unimplemented");
});
