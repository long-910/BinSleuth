# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-03-22

### Added

- **`AnalysisReport` unified struct** (`src/analyzer/mod.rs`): single entry point for all analysis results.
  - `AnalysisReport::analyze(&data)` — runs hardening + entropy analysis in one call.
  - `to_json() -> String` and `to_json_pretty() -> String` — return JSON strings directly (no stdout side-effect), designed for library consumers such as VS Code extensions.
  - `security_score: u8` — aggregate security score in [0, 100] based on weighted hardening checks (NX 20, PIE 20, RELRO 15, Stack Canary 15, FORTIFY_SOURCE 10, No-RPATH 10, Stripped 5, clean symbols 5).
- **`binsleuth::analyze(&data)`** — top-level convenience function in `lib.rs`; equivalent to `AnalysisReport::analyze`.
- **`SectionPermissions`** (`src/analyzer/entropy.rs`): new `read`, `write`, `execute` bool fields derived from ELF `SHF_*` flags and PE/COFF `IMAGE_SCN_MEM_*` characteristics.
- **`SectionEntropy` — new fields**:
  - `virtual_address: u64` — load address for memory-map visualisation.
  - `file_offset: u64` — byte offset within the file.
  - `permissions: SectionPermissions` — per-section rwx flags.
- **`SymbolCategory`** enum (`Exec` / `Net` / `Mem`) and **`DangerousSymbol { name, category }`** struct — enables category-aware visualisation (e.g. colour-coded by threat type in a VS Code extension).
- Terminal report now shows symbol category (`[exec]` / `[net]` / `[mem]`) next to each dangerous symbol.
- JSON output (`--json`) now includes a top-level `security_score` field.
- `examples/basic.rs` updated to demonstrate the new `AnalysisReport` API with virtual addresses, file offsets, and rwx permissions.
- **41 new tests** (unit + integration):
  - `extract_permissions` for ELF `SHF_*` and COFF `IMAGE_SCN_MEM_*` flags (6 unit tests).
  - `SectionEntropy::analyze` metadata validation on self-binary (2 unit tests).
  - `categorize_dangerous_symbol` for all three categories and safe symbols (8 unit tests).
  - `compute_score` boundary values, per-check deductions, clamping (9 unit tests).
  - `AnalysisReport` API: `analyze`, `to_json`, `to_json_pretty`, invalid inputs (7 unit tests).
  - CLI integration: `security_score`, `virtual_address`, `file_offset`, `permissions`, dangerous-symbol categories (6 integration tests).

### Changed

- **Breaking (library)**: `HardeningInfo::dangerous_symbols` changed from `Vec<String>` to `Vec<DangerousSymbol>`. Each entry now carries a `category: SymbolCategory` field.
- `src/analyzer/mod.rs` expanded from a stub to the home of `AnalysisReport` and `compute_score`.
- `report::json::print_json` signature changed to accept `&AnalysisReport` instead of separate `&HardeningInfo` + `&[SectionEntropy]`.
- Version bumped to `0.4.0`.

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

[Unreleased]: https://github.com/long-910/BinSleuth/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/long-910/BinSleuth/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/long-910/BinSleuth/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/long-910/BinSleuth/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/long-910/BinSleuth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/long-910/BinSleuth/releases/tag/v0.1.0
