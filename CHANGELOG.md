# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-03-15

### Added

- **FORTIFY_SOURCE detection**: new `fortify_source` field in `HardeningInfo`.
  Scans symbol tables for fortified libc wrappers (`__*_chk`, e.g. `__memcpy_chk`)
  to detect `-D_FORTIFY_SOURCE=1/2` compile-time hardening. Applies to both ELF and PE.
- **RPATH/RUNPATH detection**: new `rpath` field in `HardeningInfo` (ELF only; `N/A` for PE).
  Scans the ELF dynamic section for `DT_RPATH` (tag 15) and `DT_RUNPATH` (tag 29) entries.
  A non-empty path can allow library-injection attacks via world-writable or relative directories.
  Returns `Enabled` (safe / no path set), `Disabled` (path present), or `NotApplicable` (static binary).
- Both fields are included in JSON output and shown in the terminal "Security Hardening" section.
- 2 new unit tests: `fortify_source_disabled_for_empty_object`, `rpath_result_on_self_is_valid`.
- Updated integration test `json_hardening_contains_expected_fields` to verify the two new JSON keys.
- Updated all README files (EN / JA / ZH): hardening table, example output, supported-formats table,
  test count, and roadmap.

## [0.2.1] - 2026-03-09

### Added

- `src/lib.rs`: library crate root — `binsleuth` is now usable as a Rust library in addition to a CLI tool
- `[lib]` target declaration in `Cargo.toml` — fixes `error: no library targets found` on docs.rs
- `[package.metadata.docs.rs]` with `all-features = true` — enables proper docs.rs build configuration
- `examples/basic.rs`: runnable example demonstrating `HardeningInfo::analyze` and `SectionEntropy::analyze` via the public library API
- Library usage section in README (EN / JA / ZH)

### Fixed

- docs.rs CI was failing with `error: no library targets found in package 'binsleuth'` because the crate had no library target; adding `src/lib.rs` resolves this

### Changed

- `src/main.rs` now imports from the `binsleuth` library crate (`use binsleuth::...`) instead of declaring inline modules

## [0.2.0] - 2026-03-08

### Added

- `--json` flag: output analysis results as pretty-printed JSON (enables scripting and CI integration)
- `--strict` flag: exit with code 2 when any hardening protection is missing or dangerous symbols are detected (useful in CI pipelines)
- **Debug symbols / stripped detection**: new `stripped` field in `HardeningInfo` and terminal report
  - ELF: detects embedded DWARF debug sections (`.debug_*`)
  - PE: detects debug directory (IMAGE_DIRECTORY_ENTRY_DEBUG) and embedded `.debug_*` sections
- `serde` / `serde_json` serialization for `CheckResult`, `HardeningInfo`, and `SectionEntropy`
- 10 new integration tests covering JSON output validity, strict mode, and stripped detection (total: 42 tests)

## [0.1.0] - 2026-03-06

### Added

- ELF hardening checks: RELRO (none / partial / full), stack canary, NX, PIE, RPATH/RUNPATH detection
- PE hardening checks: NX (`IMAGE_DLLCHARACTERISTICS_NX_COMPAT`), PIE (`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`), signed binary detection
- Section-level Shannon entropy analysis with configurable thresholds
- Colored terminal output via `colored` crate
- `--verbose` flag for per-section entropy details
- `--version` / `--help` via `clap` derive macros
- Multilingual documentation: English, Japanese (`README.ja.md`), Simplified Chinese (`README.zh.md`)
- CI/CD: GitHub Actions workflows for build, test, clippy, MSRV, and release
- 32 unit + integration tests covering all analyzers and CLI edge cases
- Rust edition 2024 with MSRV 1.85

[Unreleased]: https://github.com/long-910/BinSleuth/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/long-910/BinSleuth/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/long-910/BinSleuth/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/long-910/BinSleuth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/long-910/BinSleuth/releases/tag/v0.1.0
