# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
