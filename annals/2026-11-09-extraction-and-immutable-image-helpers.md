# Extract BinaryBloodhound and use immutable image helpers

- Date: 2026-11-09
- Status: accepted; implementation in progress
- Scope: BinaryBloodhound extraction and PatternSleuth image fixture interface
- Repository: https://github.com/Jacoby6000/binarybloodhound
- Git at recording: unborn `main`; no HEAD, tags, or commits. All implementation files are untracked.
- Related repository: https://github.com/trumank/patternsleuth; working branch `feature/memory-testkit` at `afbfd00ef0541434f1aa9549dd7eb5e73ac5f12e`, with uncommitted helper changes. The dependency uses the Jacoby6000 fork.
- Source: user and build agent, session `ses_e3e9599b6ffeKmKK1iV1c4j1D5`, through response `msg_1c2c47353001q38TMK9LcOtk9K`. Earlier history is compacted.

## Subsequent developments (2026-11-09)

The statements below that the upstream helpers are uncommitted and unavailable on the dependency branch are superseded: they were committed and pushed. See [upstream helper publication](2026-11-09-upstream-helper-publication.md). Extraction completion remains unverified.

## Decision and context

The user chose BinaryBloodhound as a separate repository for the binary matcher library and requested a Cargo dependency on PatternSleuth's `feature/memory-testkit` branch. The package is `binary_bloodhound`. The matcher code was copied from PatternSleuth's matcher branch, not removed from upstream master.

Earlier, a proposed upstream fixture package was rejected: the user observed that an external crate could provide those tools, so the upstream change was narrowed to public `Image`, `NamedMemorySection`, and `Memory` construction. The testkit package was removed in PatternSleuth commit `f4b0d7943de68aad162d0cac0df0db7a0c2a24d6`. The user then preferred immutable access; commit `8f1a95b16b0015af742e902cf107af52edb88e3b` removed the new mutable accessors.

During extraction, fixture tests needed to add or remove sections and replace text without private field access. The user requested upstream `with_section`, `without_section`, `with_text`, and `copy_sections` helpers, all immutable. The user chose replacement bytes for `with_text` over a callback editing a private copy. The agent interpreted immutability as borrowing `&self` and returning new values, preserving the original.

## Evidence, tradeoffs, and status

- The untracked `Cargo.toml` selects the fork's feature branch and forwards PE, ELF, and symbols features. The transcript reports a successful library and example check against that branch; this does not establish passing extraction tests.
- The upstream worktree has uncommitted helper and test changes. The source transcript reports 12 passing memory integration tests with PE, ELF, and symbols, and 11 each for PE-only and ELF-only. These results are not independently rerun here.
- The source transcript records extraction test compilation failures, including borrowed callbacks requiring a different `eval` lifetime signature. The agent identified that signature on the older matcher branch and kept it separate from the helper changes. A successful full extraction test run remains unverified.
- Returning new images avoids mutable public access but introduces cloning and potential copying. The helper changes are not committed or published in the dependency branch, so consumers cannot yet rely on them from that branch. Integration and lifetime compatibility need resolution before declaring extraction complete.

## Reconsideration and gaps

Revisit the interface if actual fixture use, copy cost, metadata consistency, or integration tests show it insufficient. The precise upstream release or merge plan is unknown. The conversation's earlier history is available only as a compaction summary; no inference of broader consensus is intended. No issue, PR, release tag, or BinaryBloodhound implementation commit was identified.
