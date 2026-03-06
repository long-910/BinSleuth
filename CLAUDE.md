# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

```bash
# Build
cargo build
cargo build --release

# Run
cargo run -- <path-to-binary>
cargo run -- --verbose <path-to-binary>

# All tests (unit + integration)
cargo test

# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test cli

# Single test by name
cargo test --lib entropy::tests::max_entropy_for_random_distribution
cargo test --test cli self_analysis_exits_zero

# Lint (warnings = errors, as in CI)
cargo clippy --all-targets --all-features -- -D warnings

# Format
cargo fmt --all
```

## Architecture

### Data Flow

```
main.rs (CLI / clap)
  └─▶ HardeningInfo::analyze(&data)   →  src/analyzer/hardening.rs
  └─▶ SectionEntropy::analyze(&data)  →  src/analyzer/entropy.rs
  └─▶ TerminalReporter::print_report  →  src/report/terminal.rs
```

### Module Layout

| Path | Responsibility |
|------|----------------|
| `src/main.rs` | CLI parsing (`clap` derive), file I/O, wires the three pipeline stages |
| `src/analyzer/hardening.rs` | Parses raw ELF/PE bytes via the `object` crate; returns `HardeningInfo` |
| `src/analyzer/entropy.rs` | Computes per-section Shannon entropy; returns `Vec<SectionEntropy>` |
| `src/report/terminal.rs` | Formats and prints a coloured terminal report; threshold constant lives here |
| `tests/cli.rs` | Black-box integration tests — spawn the compiled binary as a child process |

### Key Types

- **`CheckResult`** (`src/analyzer/hardening.rs`) — tri-state enum: `Enabled`, `Partial(String)`, `Disabled`, `NotApplicable`. Used for every hardening flag.
- **`HardeningInfo`** — aggregates `CheckResult` fields for NX, PIE, RELRO, stack canary, plus `dangerous_symbols: Vec<String>`.
- **`SectionEntropy`** — holds section name, entropy `f64` in `[0.0, 8.0]`, and raw byte size.

### ELF vs PE Branching

`HardeningInfo::analyze` dispatches on `object::FileKind`:
- ELF 32/64: raw header parsing via `object::elf::FileHeader{32,64}` + program header iteration for NX, PIE (ET_DYN check), RELRO, BIND_NOW.
- PE 32/64: raw byte walking from `e_lfanew` to `DllCharacteristics` offset 70 in the optional header.
- Stack canary and dangerous symbol detection use `object::Object` symbol iterator for both formats.

### Entropy Threshold

`ENTROPY_WARN_THRESHOLD = 7.0` in `src/report/terminal.rs`. Sections above this are flagged as potentially packed/encrypted.

## Toolchain

- Rust edition **2024**, MSRV **1.85**
- Dependencies: `object 0.38`, `clap 4.5` (derive), `anyhow 1.0`, `colored 3.0`
