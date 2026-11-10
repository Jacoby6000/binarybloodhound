# Checks

The Rust toolchain configuration installs Clippy and rustfmt through rustup.

```sh
cargo fmt --all                       # Format code
rustfmt src/tests/shared.rs           # Format the include!-based tests
cargo fmt --all -- --check            # Check formatting
rustfmt --check src/tests/shared.rs   # Check the include!-based tests
cargo typecheck --all-features        # Compile-check library, tests, and examples
cargo lint --all-features             # Run Clippy
```

Compiler warnings and Clippy's standard lints are errors. Rust's compiler provides
strict type checking; no separate type checker is needed.

CI checks default features, all features, PE-only, and ELF-only builds. To check a
single backend locally, replace `--all-features` with
`--no-default-features --features image-pe` or
`--no-default-features --features image-elf`. At least one backend is required.

These checks compile tests but do not run them; use `cargo test` separately.
