//! Original: <https://github.com/Jacoby6000/patternsleuth/blob/3de6cfae694a95db619eddb989f0e2a9c0891ac6/patternsleuth/src/resolvers/unreal/uobject_conditional_post_load.rs>

use super::util;
use binary_bloodhound::BinaryMatcher;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use itertools::Itertools;
use patternsleuth::MemoryTrait;
use patternsleuth::resolvers::{ensure_one, impl_resolver_singleton};

fn is_volatile_register(register: Register) -> bool {
    matches!(
        register,
        Register::RAX | Register::RCX | Register::RDX | Register::R8 | Register::R9
    )
}

fn match_postloading_assignments_tail(
    instructions: &[Instruction],
    local_index: &mut usize,
    matched_address: u64,
    try_match_tails_against_lea_register: Option<Register>,
    object_source_register: Register,
) -> bool {
    // mov qword [rdi+0x90], $object_source_register
    if *local_index + 1 < instructions.len()
        && instructions[*local_index].mnemonic() == Mnemonic::Mov
        && instructions[*local_index].op0_kind() == OpKind::Memory
        && instructions[*local_index].op1_kind() == OpKind::Register
        && instructions[*local_index].op1_register() == object_source_register
    {
        let async_package_register = instructions[*local_index].memory_base();
        *local_index += 1;

        if let Some(lea_storage_register) = try_match_tails_against_lea_register {
            // mov qword [rdi+0x98], $lea_storage_register
            if !is_volatile_register(async_package_register)
                && instructions[*local_index].mnemonic() == Mnemonic::Mov
                && instructions[*local_index].op0_kind() == OpKind::Memory
                && instructions[*local_index].op1_kind() == OpKind::Register
                && instructions[*local_index].op1_register() == lea_storage_register
                && instructions[*local_index].memory_base() == async_package_register
            {
                return true;
            }
        } else {
            // We have not matched inline or persistent lea before the tail, so we could have inline lea right before assignment. Handle this case here
            if instructions[*local_index].mnemonic() == Mnemonic::Lea
                && instructions[*local_index].op0_kind() == OpKind::Register
                && instructions[*local_index].op1_kind() == OpKind::Memory
                && instructions[*local_index].is_ip_rel_memory_operand()
            {
                let lea_instruction_address = instructions[*local_index].ip();
                let lea_destination_register = instructions[*local_index].op0_register();

                if lea_instruction_address == matched_address
                    && is_volatile_register(lea_destination_register)
                {
                    *local_index += 1;

                    // mov qword [rdi+0x98], lea_destination_register
                    if !is_volatile_register(async_package_register)
                        && instructions[*local_index].mnemonic() == Mnemonic::Mov
                        && instructions[*local_index].op0_kind() == OpKind::Memory
                        && instructions[*local_index].op1_kind() == OpKind::Register
                        && instructions[*local_index].op1_register() == lea_destination_register
                        && instructions[*local_index].memory_base() == async_package_register
                    {
                        return true;
                    }
                }
            }
        }
    }

    // Permutation with $lea_storage_register being read first. Observed commonly together with inline lea
    // mov qword [rdi+0x98], $lea_storage_register
    if let Some(lea_storage_register) = try_match_tails_against_lea_register
        && *local_index + 1 < instructions.len()
        && instructions[*local_index].mnemonic() == Mnemonic::Mov
        && instructions[*local_index].op0_kind() == OpKind::Memory
        && instructions[*local_index].op1_kind() == OpKind::Register
        && instructions[*local_index].op1_register() == lea_storage_register
    {
        let async_package_register = instructions[*local_index].memory_base();
        *local_index += 1;

        // mov qword [rdi+0x90], $object_source_register
        if !is_volatile_register(async_package_register)
            && instructions[*local_index].mnemonic() == Mnemonic::Mov
            && instructions[*local_index].op0_kind() == OpKind::Memory
            && instructions[*local_index].op1_kind() == OpKind::Register
            && instructions[*local_index].op1_register() == object_source_register
            && instructions[*local_index].memory_base() == async_package_register
        {
            return true;
        }
    }
    false
}

pub use super::models::objects::UObjectConditionalPostLoad;
impl_resolver_singleton!(all, UObjectConditionalPostLoad, |ctx| async {
    enum Directness {
        Indirect,
        Direct,
    }
    let matched_addresses = BinaryMatcher::tagged_capture_patterns([
        (Directness::Indirect, util::utf16_pattern("postloading\0")), // 4.0-4.7
        (Directness::Indirect, util::utf16_pattern("postloading_async\0")), // 4.8+
        (Directness::Direct, util::utf16_pattern("%s failed to route PostLoad.  Please call Super::PostLoad() in your <className>::PostLoad() function.\0")), // Dev builds
    ])?
    .try_flat_map(|node| {
        let address = node.address;
        BinaryMatcher::patterns([
            format!("48 8d ?? X0x{address:08x}"),
            format!("4c 8d ?? X0x{address:08x}"),
        ])
    })
    .resolve(ctx)
    .await?;

    let mut conditional_post_load_addresses = Vec::new();

    for node in matched_addresses {
        let matched_address = *node.value;
        let pattern_tag = node.parent().outer.tag.as_ref();
        let Some(function) = ctx.image().get_root_function(matched_address)? else {
            continue;
        };
        let function_start_address = function.range.start;

        match pattern_tag {
            Directness::Indirect => {
                let function_disassembly_length = 0x500; // Allow room for flags and debug assertions.
                let bytes = ctx.image().memory.range(
                    function_start_address..function_start_address + function_disassembly_length,
                )?;
                let instructions =
                    Decoder::with_ip(64, bytes, function_start_address, DecoderOptions::NONE)
                        .iter()
                        .collect_vec();
                let mut candidates: Vec<(Register, u64)> = Vec::new();
                let mut index = 0;
                let mut persistent_lea_storage_register: Option<Register> = None;

                while index < instructions.len() {
                    let mut local_index = index;

                    // We are looking for something similar to this here:
                    // mov rcx, rbx
                    if local_index + 1 < instructions.len()
                        && instructions[local_index].mnemonic() == Mnemonic::Mov
                        && instructions[local_index].op0_kind() == OpKind::Register
                        && instructions[local_index].op0_register() == Register::RCX
                        && instructions[local_index].op1_kind() == OpKind::Register
                    {
                        let object_source_register = instructions[local_index].op1_register();
                        local_index += 1;

                        // Some UE versions (most of them actually) have CurrentlyPostLoadedObjectByALT being set before and after the call
                        // mov qword [mem], $object_source_register
                        if local_index + 1 < instructions.len()
                            && instructions[local_index].mnemonic() == Mnemonic::Mov
                            && instructions[local_index].op0_kind() == OpKind::Memory
                            && instructions[local_index].op1_kind() == OpKind::Register
                            && instructions[local_index].op1_register() == object_source_register
                        {
                            local_index += 1;
                        }

                        // call UObject::ConditionalPostLoad
                        if local_index + 1 < instructions.len()
                            && instructions[local_index].mnemonic() == Mnemonic::Call
                            && instructions[local_index].op0_kind() == OpKind::NearBranch64
                            && !is_volatile_register(object_source_register)
                        {
                            let call_target_address = instructions[local_index].near_branch64();
                            local_index += 1;

                            // We have matched a potential ConditionalPostLoad candidate, we just need to associate it with a lea
                            // That could happen immediately in the same iteration (if there are no extra instructions in-between) or with some instructions
                            // between the call and the tail (development builds, UE 4.25 builds and other cases)
                            index = local_index;
                            candidates.push((object_source_register, call_target_address));
                        }
                    }

                    let mut try_match_tails_against_lea_register: Option<Register> =
                        persistent_lea_storage_register;

                    // Try to match inline lea or persistent lea instruction. Note that there is a case when lea is followed by object pointer assignment (when it is inline),
                    // which we also attempt to match against during match_postloading_assignments_tail
                    // lea $destination_register, [rip+0x00]
                    if instructions[local_index].mnemonic() == Mnemonic::Lea
                        && instructions[local_index].op0_kind() == OpKind::Register
                        && instructions[local_index].op1_kind() == OpKind::Memory
                        && instructions[local_index].is_ip_rel_memory_operand()
                    {
                        let lea_instruction_address = instructions[local_index].ip();
                        let lea_destination_register = instructions[local_index].op0_register();

                        if lea_instruction_address == matched_address {
                            // This is the lea by which we have identified this function. This could be a persistent lea or inline lea, depending on whenever
                            // destination register is a volatile register or not
                            local_index += 1;

                            if is_volatile_register(lea_destination_register) {
                                // This is a volatile lea, do not store its destination as persistent_lea_storage_register, only try to match against it this iteration
                                try_match_tails_against_lea_register =
                                    Some(lea_destination_register);
                            } else {
                                // This is a lea with a persistent register, we want to match all tails against it from now on
                                persistent_lea_storage_register = Some(lea_destination_register);
                                try_match_tails_against_lea_register =
                                    persistent_lea_storage_register;
                                index = local_index;
                            }
                        }
                    }

                    // If we have a known lea register to match tails against, try to do so
                    if instructions[local_index].mnemonic() == Mnemonic::Mov
                        && instructions[local_index].op0_kind() == OpKind::Memory
                    {
                        // Prefer the latest call over earlier UObject calls such as GetStatID.
                        let candidate = candidates.iter().rev().find(|candidate| {
                            let mut local_index_copy = local_index;
                            match_postloading_assignments_tail(
                                &instructions,
                                &mut local_index_copy,
                                matched_address,
                                try_match_tails_against_lea_register,
                                candidate.0,
                            )
                        });
                        if let Some((_, target)) = candidate {
                            conditional_post_load_addresses.push(*target);
                            break;
                        }
                    }

                    // Do not match past function return statement
                    if instructions[index].mnemonic() == Mnemonic::Ret {
                        break;
                    }

                    // Advance the instruction pointer
                    index += 1;
                }
            }
            Directness::Direct => {
                conditional_post_load_addresses.push(function_start_address);
            }
        }
    }

    Ok(Self(ensure_one(conditional_post_load_addresses)?))
});
