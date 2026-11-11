use std::collections::HashSet;

use iced_x86::{Decoder, DecoderOptions, FlowControl};
use patternsleuth::{
    MemoryAccessError, MemoryTrait, RuntimeFunction,
    image::Image,
    resolvers::{ResolveError, Result},
};

use crate::{Address, Call, FunctionEntry, InstructionSite, MatchContext};

pub(super) fn root_entry(image: &Image<'_>, address: u64) -> Result<Option<FunctionEntry>> {
    let Some(function) = root_function(image, address)? else {
        return Ok(None);
    };
    if function.range.end < function.range.start {
        return Err(ResolveError::new_msg(format!(
            "invalid function range: {:#x}..{:#x}",
            function.range.start, function.range.end
        )));
    }
    Ok(Some(FunctionEntry {
        start: function.range.start,
        end: function.range.end,
        unwind: (function.unwind != 0).then_some(function.unwind),
    }))
}

fn root_function(
    image: &Image<'_>,
    address: u64,
) -> std::result::Result<Option<RuntimeFunction>, MemoryAccessError> {
    match &image.image_type {
        #[cfg(feature = "image-pe")]
        patternsleuth::image::ImageType::PEImage(pe) => {
            let range = &pe.exception_directory_range;
            let length = range
                .end
                .checked_sub(range.start)
                .ok_or(MemoryAccessError::MemoryOutOfBoundsError)?;
            if length == 0 {
                return Ok(None);
            }
            if length < 12 {
                return Err(MemoryAccessError::MemoryOutOfBoundsError);
            }
            let first = image
                .base_address
                .checked_add(u64::from(image.memory.u32_le(range.start)?))
                .ok_or(MemoryAccessError::MemoryOutOfBoundsError)?;
            // Upstream's inclusive search underflows on empty tables and addresses before the first entry.
            if address < first {
                return Ok(None);
            }
        }
        #[cfg(feature = "image-elf")]
        patternsleuth::image::ImageType::ElfImage(_) => {}
    }
    image.get_root_function(address)
}

/// Visit reachable blocks without following branches outside the containing root.
pub(super) fn function_calls(ctx: MatchContext<'_, '_>, address: u64) -> Result<Vec<Call>> {
    let image = ctx.image();
    let Some(root) = root_function(image, address)? else {
        return Ok(Vec::new());
    };
    let entry = root.range.start;
    let bounds = ctx.bounds();
    let start = bounds
        .as_ref()
        .map_or(entry, |range| entry.max(range.start));
    let mut pending = vec![start];
    let mut visited = HashSet::new();
    let mut calls = Vec::new();
    while let Some(block) = pending.pop() {
        if visited.contains(&block)
            || bounds.as_ref().is_some_and(|range| !range.contains(&block))
            || root_function(image, block)?.map(|f| f.range.start) != Some(entry)
        {
            continue;
        }
        let bytes = image.memory.range_from(block..)?;
        let length = bounds.as_ref().map_or(bytes.len(), |range| {
            usize::try_from(range.end - block)
                .unwrap_or(usize::MAX)
                .min(bytes.len())
        });
        let mut decoder = Decoder::with_ip(64, &bytes[..length], block, DecoderOptions::NONE);
        while decoder.can_decode() {
            let ip = decoder.ip();
            if root_function(image, ip)?.map(|f| f.range.start) != Some(entry)
                || !visited.insert(ip)
            {
                break;
            }
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                if bounds.is_some() && decoder.last_error() == iced_x86::DecoderError::NoMoreBytes {
                    break;
                }
                return Err(ResolveError::new_msg(format!(
                    "invalid instruction at {ip:#x}"
                )));
            }
            match instruction.flow_control() {
                FlowControl::Call if instruction.is_call_near() => calls.push(Call {
                    site: InstructionSite(ip),
                    target: Address(instruction.near_branch_target()),
                }),
                FlowControl::ConditionalBranch => pending.push(instruction.near_branch_target()),
                FlowControl::UnconditionalBranch => {
                    pending.push(instruction.near_branch_target());
                    break;
                }
                FlowControl::Return | FlowControl::IndirectBranch | FlowControl::Exception => break,
                _ => {}
            }
        }
    }
    calls.sort_unstable_by_key(|call| call.site.0);
    Ok(calls)
}
