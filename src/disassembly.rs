use std::collections::HashSet;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use patternsleuth::{
    MemoryTrait,
    resolvers::{ResolveError, Result},
};

use crate::{FunctionEntry, MatchContext};

/// Control a branch-local disassembly fold. Only Return emits a candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control<S, R> {
    /// Continue normal traversal with replacement state.
    Continue(S),
    /// Enter a direct call/jump target now; queue the next instruction with cloned state.
    /// Other instructions fall through, including return instructions.
    Follow(S),
    /// Emit a result, discard this branch's state, and resume a queued branch.
    Return(R),
    /// Discard this branch without emitting; resume a queued branch.
    Break,
    /// Stop this function's entire walk, retaining results already emitted.
    Exit,
}

pub(crate) fn walk<S: Clone, R>(
    ctx: MatchContext<'_, '_>,
    function: FunctionEntry,
    initial: S,
    visitor: &impl Fn(S, &Instruction) -> Result<Control<S, R>>,
) -> Result<Vec<R>> {
    use patternsleuth::disassemble::{Control as NativeControl, disassemble};

    function.checked_range()?;
    let bounds = ctx.bounds();
    let start = bounds
        .as_ref()
        .map_or(function.start, |range| function.start.max(range.start));
    if start >= function.end || bounds.as_ref().is_some_and(|range| !range.contains(&start)) {
        return Ok(Vec::new());
    }
    let mut active = Some((start, initial));
    let mut pending = Vec::new();
    let mut visited = HashSet::new();
    let mut results = Vec::new();
    let mut visitor_error = None;
    disassemble(ctx.image(), start, |instruction| {
        // Upstream silently pops paths whose first instruction was already visited.
        // Mirror its address stack only to select state; upstream still owns all decoding.
        while active.as_ref().is_some_and(|(ip, _)| visited.contains(ip)) {
            active = pending.pop();
        }
        let Some((ip, state)) = active.take() else {
            visitor_error = Some(ResolveError::new_msg("missing disassembly branch state"));
            return Ok(NativeControl::Exit);
        };
        if ip != instruction.ip() {
            visitor_error = Some(ResolveError::new_msg(
                "disassembly branch state out of sync",
            ));
            return Ok(NativeControl::Exit);
        }
        visited.insert(ip);
        if bounds
            .as_ref()
            .is_some_and(|range| !range.contains(&ip) || instruction.next_ip() > range.end)
        {
            active = pending.pop();
            return Ok(NativeControl::Break);
        }
        if instruction.is_invalid() {
            visitor_error = Some(ResolveError::new_msg(format!(
                "invalid instruction at {ip:#x}"
            )));
            return Ok(NativeControl::Exit);
        }
        let control = match visitor(state, instruction) {
            Ok(control) => control,
            Err(error) => {
                visitor_error = Some(error);
                return Ok(NativeControl::Exit);
            }
        };
        let next = instruction.next_ip();
        Ok(match control {
            Control::Continue(state) => {
                match instruction.flow_control() {
                    FlowControl::UnconditionalBranch => {
                        active = Some((instruction.near_branch_target(), state))
                    }
                    FlowControl::ConditionalBranch => {
                        pending.push((instruction.near_branch_target(), state.clone()));
                        active = Some((next, state));
                    }
                    FlowControl::Return => active = pending.pop(),
                    _ => active = Some((next, state)),
                }
                NativeControl::Continue
            }
            Control::Follow(state) => {
                if matches!(
                    instruction.flow_control(),
                    FlowControl::Call
                        | FlowControl::UnconditionalBranch
                        | FlowControl::ConditionalBranch
                ) {
                    pending.push((next, state.clone()));
                    active = Some((instruction.near_branch_target(), state));
                } else {
                    // Native Follow skips normal flow-control handling for other instructions.
                    active = Some((next, state));
                }
                NativeControl::Follow
            }
            Control::Return(result) => {
                results.push(result);
                active = pending.pop();
                NativeControl::Break
            }
            Control::Break => {
                active = pending.pop();
                NativeControl::Break
            }
            Control::Exit => NativeControl::Exit,
        })
    })?;
    if let Some(error) = visitor_error {
        return Err(error);
    }
    Ok(results)
}

pub(crate) fn collect(
    ctx: MatchContext<'_, '_>,
    function: FunctionEntry,
    stop: &impl Fn(&Instruction) -> bool,
) -> Result<Vec<Instruction>> {
    let bounds = ctx.within(function.checked_range()?).bounds().unwrap();
    let mut pending = vec![bounds.start];
    let mut visited = HashSet::new();
    let mut instructions = Vec::new();

    while let Some(block) = pending.pop() {
        if !bounds.contains(&block) || visited.contains(&block) {
            continue;
        }
        let bytes = ctx.image().memory.range_from(block..)?;
        let length = usize::try_from(bounds.end - block)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let mut decoder = Decoder::with_ip(64, &bytes[..length], block, DecoderOptions::NONE);
        while decoder.can_decode() {
            if !visited.insert(decoder.ip()) {
                break;
            }
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                return Err(ResolveError::new_msg(format!(
                    "invalid instruction at {:#x}",
                    instruction.ip()
                )));
            }
            instructions.push(instruction);
            if stop(&instruction) {
                break;
            }
            match instruction.flow_control() {
                FlowControl::UnconditionalBranch => {
                    pending.push(instruction.near_branch_target());
                    break;
                }
                FlowControl::ConditionalBranch => pending.push(instruction.near_branch_target()),
                FlowControl::Return => break,
                _ => {}
            }
        }
    }
    Ok(instructions)
}
