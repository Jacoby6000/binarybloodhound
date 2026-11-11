fn walked_path_image() -> Image<'static> {
    let mut text = vec![0x90; 256];
    relative(&mut text, 0, &[0x0f, 0x84], TEXT + 24);
    relative(&mut text, 6, &[0x0f, 0x84], TEXT + 32);
    text[12] = 0xc3;
    text[24] = 0xc3;
    text[32] = 0xc3;
    image(text)
}

#[test]
fn walk_disassembly_returns_branch_local_fold_results_in_native_order() {
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .ensure_one()
        .walk_disassembly(
            |_| Vec::new(),
            |mut path, instruction| {
                path.push(instruction.ip());
                Ok(if instruction.flow_control() == FlowControl::Return {
                    Control::Return(path)
                } else {
                    Control::Continue(path)
                })
            },
        );
    let result = run_stage(&walked_path_image(), matcher, ()).unwrap();

    assert_eq!(
        result,
        [
            vec![TEXT, TEXT + 6, TEXT + 12],
            vec![TEXT, TEXT + 6, TEXT + 32],
            vec![TEXT, TEXT + 24],
        ]
    );
}

#[test]
fn walk_disassembly_break_discards_only_the_active_branch() {
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .walk_disassembly(
            |_| 0_u64,
            |state, instruction| {
                Ok(match instruction.ip() - TEXT {
                    12 => Control::Break,
                    24 | 32 => Control::Return(state),
                    _ => Control::Continue(state + 1),
                })
            },
        );
    let result = run_stage(&walked_path_image(), matcher, ()).unwrap();

    assert_eq!(result, [2, 1]);
}

#[test]
fn walk_disassembly_natural_returns_resume_queued_branch_state_without_emitting() {
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .walk_disassembly(
            |_| 0,
            |count, instruction| {
                Ok(match instruction.ip() - TEXT {
                    24 | 32 => Control::Return(count),
                    _ => Control::Continue(count + 1),
                })
            },
        );
    let result = run_stage(&walked_path_image(), matcher, ()).unwrap();

    assert_eq!(result, [2, 1]);
}

#[test]
fn walk_disassembly_branch_return_does_not_queue_the_instruction_target() {
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .walk_disassembly(
            |_| (),
            |(), instruction| {
                assert_eq!(instruction.ip(), TEXT);
                Ok(Control::Return(7))
            },
        );
    let result = run_stage(&walked_path_image(), matcher, ()).unwrap();

    assert_eq!(result, [7]);
}

#[test]
fn walk_disassembly_exit_retains_returns_and_skips_queued_paths() {
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .walk_disassembly(
            |_| (),
            |(), instruction| {
                Ok(match instruction.ip() - TEXT {
                    12 => Control::Return(12),
                    32 => Control::Exit,
                    24 => panic!("Exit must skip queued paths"),
                    _ => Control::Continue(()),
                })
            },
        );
    let result = run_stage(&walked_path_image(), matcher, ()).unwrap();

    assert_eq!(result, [12]);
}

#[test]
fn walk_disassembly_discards_state_on_implicit_path_end() {
    let mut text = vec![0x90; 256];
    text[0] = 0xc3;
    let matcher: Matcher<(), u64, Variable, _> = BinaryMatcher::address(TEXT)
        .root_functions()
        .walk_disassembly(|_| 7, |state, _| Ok(Control::Continue(state + 1)));
    let result = run_stage(&image(text), matcher, ()).unwrap();

    assert!(result.is_empty());
}

#[test]
fn walk_disassembly_follow_enters_calls_and_restores_the_continuation_state() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 0, &[0xe8], TEXT + 64);
    text[5] = 0xc3;
    text[64] = 0xc3;
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .walk_disassembly(
            |_| vec![],
            |mut path, instruction| {
                path.push(instruction.ip());
                Ok(if instruction.is_call_near() {
                    Control::Follow(path)
                } else {
                    Control::Return(path)
                })
            },
        );
    let result = run_stage(&image(text), matcher, ()).unwrap();

    assert_eq!(result, [vec![TEXT, TEXT + 64], vec![TEXT, TEXT + 5]]);
}

#[test]
fn walk_disassembly_continue_skips_call_targets() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 0, &[0xe8], TARGET);
    text[5] = 0xc3;
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .walk_disassembly(
            |_| 0,
            |count, instruction| {
                Ok(if instruction.is_call_near() {
                    Control::Continue(count + 1)
                } else {
                    Control::Return(count)
                })
            },
        );
    let result = run_stage(&image(text), matcher, ()).unwrap();

    assert_eq!(result, [1]);
}

#[test]
fn walk_disassembly_follow_handles_jumps_and_non_target_instructions_like_native() {
    for opcode in [&[0xe9][..], &[0x0f, 0x84][..]] {
        let mut text = vec![0x90; 256];
        relative(&mut text, 0, opcode, TEXT + 24);
        text[opcode.len() + 4] = 0xc3;
        text[24] = 0xc3;
        let matcher = BinaryMatcher::address(TEXT)
            .root_functions()
            .walk_disassembly(
                |_| 0,
                |count, instruction| {
                    Ok(if instruction.ip() == TEXT {
                        Control::Follow(count + 1)
                    } else {
                        Control::Return((count, instruction.ip()))
                    })
                },
            );
        let result = run_stage(&image(text), matcher, ()).unwrap();

        assert_eq!(
            result,
            [(1, TEXT + 24), (1, TEXT + opcode.len() as u64 + 4)]
        );
    }
}

#[test]
fn walk_disassembly_follow_on_a_return_matches_native_fallthrough() {
    let mut text = vec![0x90; 256];
    text[0] = 0xc3;
    text[1] = 0xc3;
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .walk_disassembly(
            |_| 0,
            |count, instruction| {
                Ok(if instruction.ip() == TEXT {
                    Control::Follow(count + 1)
                } else {
                    Control::Return(count)
                })
            },
        );
    let result = run_stage(&image(text), matcher, ()).unwrap();

    assert_eq!(result, [1]);
}

#[test]
fn walk_disassembly_tracks_native_silent_visited_path_pops() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 0, &[0x0f, 0x84], TEXT + 32);
    relative(&mut text, 6, &[0x0f, 0x84], TEXT + 24);
    relative(&mut text, 12, &[0x0f, 0x84], TEXT + 24);
    relative(&mut text, 18, &[0xe9], TEXT + 24);
    text[24] = 0xc3;
    text[32] = 0xc3;
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .walk_disassembly(
            |_| 0,
            |count, instruction| {
                Ok(if instruction.flow_control() == FlowControl::Return {
                    Control::Return((count, instruction.ip()))
                } else {
                    Control::Continue(count + 1)
                })
            },
        );
    let result = run_stage(&image(text), matcher, ()).unwrap();

    assert_eq!(result, [(4, TEXT + 24), (1, TEXT + 32)]);
}

#[test]
fn walk_disassembly_initializes_state_per_function_and_preserves_duplicates() {
    let mut text = vec![0x90; 256];
    text[0] = 0xc3;
    text[64] = 0xc3;
    let matcher = BinaryMatcher::candidates([TEXT, TEXT + 64, TEXT])
        .root_functions()
        .walk_disassembly(
            |_| String::from("seed"),
            |mut state, instruction| {
                state.push('!');
                Ok(Control::Return((state, instruction.ip())))
            },
        );
    let result = run_stage(&image(text), matcher, ()).unwrap();

    assert_eq!(
        result,
        [
            ("seed!".into(), TEXT),
            ("seed!".into(), TEXT + 64),
            ("seed!".into(), TEXT)
        ]
    );
}

#[test]
fn walk_disassembly_exit_does_not_skip_later_function_candidates() {
    let mut text = vec![0x90; 256];
    text[0] = 0xc3;
    text[64] = 0xc3;
    let matcher = BinaryMatcher::candidates([TEXT, TEXT + 64])
        .root_functions()
        .walk_disassembly(
            |_| (),
            |(), instruction| {
                Ok(if instruction.ip() == TEXT {
                    Control::Exit
                } else {
                    Control::Return(instruction.ip())
                })
            },
        );
    let result = run_stage(&image(text), matcher, ()).unwrap();

    assert_eq!(result, [TEXT + 64]);
}

#[test]
fn walk_disassembly_returns_can_be_non_clone_and_capture_borrowed_data() {
    struct Output(String);
    let text = String::from("borrowed");
    let matcher = functions(&[(TEXT, TEXT + 1)])
        .walk_disassembly(|_| (), |(), _| Ok(Control::Return(Output(text.clone()))));
    let result = run_nodes(&image(vec![0xc3]), matcher, ()).unwrap();

    assert_eq!(result[0].0, "borrowed");
}

#[test]
fn walk_disassembly_skips_empty_input_and_empty_function_tables() {
    let empty = functions(&[]).walk_disassembly(
        |_| (),
        |(), _| -> Result<Control<(), u64>> { panic!("empty input must skip the visitor") },
    );
    let unknown_root = BinaryMatcher::address(TEXT).walk_disassembly(
        |_| -> () { panic!("unknown roots must skip initialization") },
        |(), _| -> Result<Control<(), u64>> { panic!("unknown roots must skip the visitor") },
    );

    assert!(run_stage(&image(vec![]), empty, ()).unwrap().is_empty());
    assert!(
        run_stage(&construct_image(vec![], 0), unknown_root, ())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn walk_disassembly_propagates_visitor_errors_without_later_candidates() {
    let matcher = functions(&[(TEXT, TEXT + 1), (TEXT + 64, TEXT + 65)]).walk_disassembly(
        |_| (),
        |(), instruction| -> Result<Control<(), u64>> {
            assert_eq!(instruction.ip(), TEXT);
            Err(ResolveError::new_msg("visitor failed"))
        },
    );
    let error = run_stage(&image(vec![0x90; 256]), matcher, ()).unwrap_err();

    assert_eq!(error.to_string(), "visitor failed");
}

#[test]
fn walk_disassembly_propagates_memory_errors_from_follow() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 0, &[0xe8], TARGET);
    let matcher = BinaryMatcher::address(TEXT)
        .root_functions()
        .walk_disassembly(
            |_| (),
            |(), _| -> Result<Control<(), u64>> { Ok(Control::Follow(())) },
        );
    let error = run_stage(&image(text), matcher, ()).unwrap_err();

    assert_eq!(
        error,
        ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
    );
}

#[test]
fn walk_disassembly_rejects_invalid_instructions_before_visiting_them() {
    let matcher = functions(&[(TEXT, TEXT + 1)]).walk_disassembly(
        |_| (),
        |(), _| -> Result<Control<(), u64>> {
            panic!("invalid instructions must not reach the visitor")
        },
    );
    let error = run_stage(&image(vec![0x0f]), matcher, ()).unwrap_err();

    assert!(error.to_string().contains("invalid instruction"));
}

#[test]
fn walk_disassembly_filters_visitors_to_search_bounds() {
    let inner = functions(&[(TEXT, TEXT + 64)]).walk_disassembly(
        |_| (),
        |(), instruction| Ok(Control::Return(instruction.ip())),
    );
    let matcher = functions(&[(TEXT + 8, TEXT + 16)]).sub(inner);
    let result = run_stage(&image(vec![0x90; 256]), matcher, ()).unwrap();

    assert_eq!(result, [TEXT + 8]);
}

#[test]
fn walk_disassembly_retains_native_errors_for_unmapped_out_of_scope_targets() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 0, &[0xe9], TARGET);
    let inner = functions(&[(TEXT, TEXT + 64)]).walk_disassembly(
        |_| (),
        |(), _| -> Result<Control<(), u64>> { Ok(Control::Continue(())) },
    );
    let matcher = functions(&[(TEXT, TEXT + 8)]).sub(inner);
    let error = run_stage(&image(text), matcher, ()).unwrap_err();

    assert_eq!(
        error,
        ResolveError::from(patternsleuth::MemoryAccessError::MemoryOutOfBoundsError)
    );
}

#[test]
fn walk_disassembly_discards_out_of_scope_paths_and_resumes_queued_state() {
    let mut text = vec![0x90; 256];
    relative(&mut text, 0, &[0x0f, 0x84], TEXT + 16);
    relative(&mut text, 6, &[0xe9], TEXT + 64);
    let inner = functions(&[(TEXT, TEXT + 128)]).walk_disassembly(
        |_| 0,
        |count, instruction| {
            assert!(instruction.ip() < TEXT + 32);
            Ok(if instruction.ip() == TEXT + 16 {
                Control::Return(count)
            } else {
                Control::Continue(count + 1)
            })
        },
    );
    let matcher = functions(&[(TEXT, TEXT + 32)]).sub(inner);
    let result = run_stage(&image(text), matcher, ()).unwrap();

    assert_eq!(result, [1]);
}

#[test]
fn walk_disassembly_rejects_invalid_function_ranges() {
    let matcher = Matcher::from_async(|(), ctx| {
        Box::pin(async move {
            crate::disassembly::walk(
                ctx,
                FunctionEntry {
                    start: TEXT + 1,
                    end: TEXT,
                    unwind: None,
                },
                (),
                &|(), _| -> Result<Control<(), u64>> { panic!("invalid range") },
            )
        })
    });
    let error = run_stage(&image(vec![]), matcher, ()).unwrap_err();

    assert!(error.to_string().contains("invalid function range"));
}

#[test]
fn walk_disassembly_adapter_skips_empty_resolved_ranges() {
    let matcher = Matcher::from_async(|(), ctx| {
        Box::pin(async move {
            crate::disassembly::walk(
                ctx,
                FunctionEntry {
                    start: TEXT,
                    end: TEXT,
                    unwind: None,
                },
                (),
                &|(), _| -> Result<Control<(), u64>> { panic!("empty range") },
            )
        })
    });
    let result = run_stage(&image(vec![]), matcher, ()).unwrap();

    assert!(result.is_empty());
}

#[test]
fn walk_disassembly_initializes_from_original_addresses_but_starts_at_their_roots() {
    let matcher = BinaryMatcher::candidates([TEXT + 8, TEXT + 24, TEXT + 8]).walk_disassembly(
        |address| *address.value,
        |address, instruction| Ok(Control::Return((address, instruction.ip()))),
    );
    let result = run_stage(&image(vec![0x90; 256]), matcher, ()).unwrap();

    assert_eq!(
        result,
        [(TEXT + 8, TEXT), (TEXT + 24, TEXT), (TEXT + 8, TEXT)]
    );
}

#[test]
fn walk_disassembly_supports_non_clone_custom_address_candidates() {
    struct Source {
        address: u64,
        label: String,
    }
    impl HasAddress for Source {
        fn address(&self) -> u64 {
            self.address
        }
    }
    let matcher = Matcher::from_sync(|()| {
        Ok(vec![Source {
            address: TEXT + 8,
            label: "source".into(),
        }])
    })
    .walk_disassembly(
        |source| (source.address, source.label.clone()),
        |state, instruction| Ok(Control::Return((state, instruction.ip()))),
    );
    let result = run_stage(&image(vec![0x90; 256]), matcher, ()).unwrap();

    assert_eq!(result, [((TEXT + 8, "source".into()), TEXT)]);
}

#[test]
fn walk_disassembly_unknown_roots_do_not_call_the_initializer() {
    let matcher = BinaryMatcher::candidates([0, TEXT + 128, u64::MAX]).walk_disassembly(
        |_| -> () { panic!("unknown root") },
        |(), _| Ok(Control::Return(1)),
    );
    let result = run_stage(&scan_image(), matcher, ()).unwrap();

    assert!(result.is_empty());
}

#[test]
fn walk_disassembly_stage_accepts_raw_address_candidates() {
    let matcher = BinaryMatcher::address(TEXT + 8).then(stages::walk_disassembly(
        |address: &Trace<u64>| *address.value,
        |address, instruction| Ok(Control::Return((address, instruction.ip()))),
    ));
    let result = run_stage(&image(vec![0x90; 256]), matcher, ()).unwrap();

    assert_eq!(result, [(TEXT + 8, TEXT)]);
}

#[test]
fn walk_disassembly_reusable_stage_and_repeated_evaluations_start_fresh() {
    let matcher = functions(&[(TEXT, TEXT + 1)]).then(stages::walk_disassembly(
        |function: &Trace<FunctionEntry>| function.start,
        |count, _| Ok(Control::Return(count + 1)),
    ));
    let image = image(vec![0xc3]);
    let first = run_stage(&image, matcher.clone(), ()).unwrap();
    let second = run_stage(&image, matcher, ()).unwrap();

    assert_eq!(first, [TEXT + 1]);
    assert_eq!(second, first);
}

#[test]
fn walk_disassembly_initializer_receives_each_function_candidate() {
    let matcher = functions(&[(TEXT, TEXT + 32), (TEXT + 64, TEXT + 80)]).walk_disassembly(
        |function| (function.start, function.end, function.unwind),
        |state, _| Ok(Control::Return(state)),
    );
    let result = run_stage(&image(vec![0x90; 256]), matcher, ()).unwrap();

    assert_eq!(
        result,
        [(TEXT, TEXT + 32, None), (TEXT + 64, TEXT + 80, None)]
    );
}

#[test]
fn walk_disassembly_initializes_once_per_candidate_not_per_branch() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let calls = AtomicUsize::new(0);
    let matcher = functions(&[(TEXT, TEXT + 64)]).walk_disassembly(
        |function| {
            calls.fetch_add(1, Ordering::SeqCst);
            function.start
        },
        |start, instruction| {
            Ok(if instruction.flow_control() == FlowControl::Return {
                Control::Return(start)
            } else {
                Control::Continue(start)
            })
        },
    );
    let result = run_stage(&walked_path_image(), matcher, ()).unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(result, [TEXT, TEXT, TEXT]);
}

#[test]
fn walk_disassembly_empty_input_skips_the_initializer() {
    let matcher = functions(&[]).walk_disassembly(
        |_| -> () { panic!("empty input must skip initialization") },
        |(), _| Ok(Control::Return(1)),
    );
    let result = run_stage(&image(vec![]), matcher, ()).unwrap();

    assert!(result.is_empty());
}

#[test]
fn walk_disassembly_state_does_not_require_sync() {
    use std::cell::RefCell;

    let matcher = functions(&[(TEXT, TEXT + 1)]).walk_disassembly(
        |function| RefCell::new(function.start),
        |state, _| Ok(Control::Return(state.into_inner())),
    );
    let result = run_stage(&image(vec![0xc3]), matcher, ()).unwrap();

    assert_eq!(result, [TEXT]);
}

#[test]
fn walk_disassembly_control_traces_match_native_across_branch_graphs() {
    use patternsleuth::disassemble::{Control as NativeControl, disassemble};
    use std::sync::{Arc, Mutex};

    for seed in 0..64_u64 {
        let mut text = vec![0x90; 256];
        for slot in 0..8 {
            let target = TEXT + ((slot as u64 * 3 + seed) % 8) * 8;
            match (slot as u64 + seed) % 4 {
                0 => relative(&mut text, slot * 8, &[0x0f, 0x84], target),
                1 => relative(&mut text, slot * 8, &[0xe8], target),
                2 => relative(&mut text, slot * 8, &[0xe9], target),
                _ => text[slot * 8] = 0xc3,
            }
        }
        let action = move |ip: u64| {
            let offset = ip - TEXT;
            if offset >= 64 {
                3
            } else if offset.is_multiple_of(8) {
                (offset / 8 + seed / 4) % 5
            } else {
                0
            }
        };
        let image = image(text);
        let mut native_trace = Vec::new();
        let mut native_results = Vec::new();
        disassemble(&image, TEXT, |instruction| {
            native_trace.push(instruction.ip());
            Ok(match action(instruction.ip()) {
                0 => NativeControl::Continue,
                1 => NativeControl::Follow,
                2 => NativeControl::Break,
                3 => NativeControl::Exit,
                _ => {
                    native_results.push(instruction.ip());
                    NativeControl::Break
                }
            })
        })
        .unwrap();
        let trace = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&trace);
        let matcher = BinaryMatcher::address(TEXT)
            .root_functions()
            .walk_disassembly(
                |_| (),
                move |(), instruction| {
                    observed.lock().unwrap().push(instruction.ip());
                    Ok(match action(instruction.ip()) {
                        0 => Control::Continue(()),
                        1 => Control::Follow(()),
                        2 => Control::Break,
                        3 => Control::Exit,
                        _ => Control::Return(instruction.ip()),
                    })
                },
            );
        let result = run_stage(&image, matcher, ()).unwrap();

        assert_eq!(*trace.lock().unwrap(), native_trace, "seed {seed}");
        assert_eq!(result, native_results, "seed {seed}");
    }
}
