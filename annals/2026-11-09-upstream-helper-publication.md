# Publish immutable image helpers on the dependency branch

- Date: 2026-11-09
- Status: implemented on feature branch; extraction in progress
- Scope: PatternSleuth image helpers used by BinaryBloodhound tests
- Repository: https://github.com/Jacoby6000/binarybloodhound
- Git at recording: `main`, `102c22a7875dcbf3801333201266fe8974f28dfc`; no tag at HEAD. Implementation files remain untracked.
- Related repository: https://github.com/Jacoby6000/patternsleuth, `feature/memory-testkit`, commit `03fa32d01cedb74822946916af10c3b6f14df7bb`; upstream canonical repository is https://github.com/trumank/patternsleuth.
- Source: user and build agent, session `ses_e3e9599b6ffeKmKK1iV1c4j1D5`, response `msg_1c2f08dfa001BBP6emy0u6ynSJ`; earlier conversation is compacted.

## Change and evidence

The user requested commit and push of the immutable helper work described in [the extraction decision](2026-11-09-extraction-and-immutable-image-helpers.md). The earlier record's claims that these helpers were uncommitted and unavailable on the dependency branch were accurate at that time but are now superseded.

The related worktree's commit `03fa32d` contains the helpers, and the source transcript records a successful push to the fork's `feature/memory-testkit`. The helpers use `&self` and return new values; `with_text` accepts replacement bytes. The transcript reports 12 memory tests passing with PE, ELF and symbols and 11 each for PE-only and ELF-only. These tests were not rerun in this review.

## Consequences and open questions

BinaryBloodhound's extraction remains uncommitted and its full tests were not demonstrated passing. The transcript records borrowed-callback compilation failures associated with the older `eval` lifetime signature; whether the proposed lifetime fix fully resolves integration is unverified. Reconsider the interface if fixture integration, metadata consistency, or cloning cost proves problematic. The upstream merge and release plan is unknown; no PR or release tag was identified. No alternative to publishing this already accepted helper implementation was documented.
