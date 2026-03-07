# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/long-910/BinSleuth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/long-910/BinSleuth/releases/tag/v0.1.0
