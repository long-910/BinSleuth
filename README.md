<div align="center">

# 🔍 BinSleuth

**A fast, zero-dependency CLI tool for static binary security analysis.**
Inspect ELF & PE binaries for hardening flags and detect packed/encrypted sections — in milliseconds.

![BinSleuth social preview](https://repository-images.githubusercontent.com/1174345949/ddfc9174-be34-4b79-931d-1b8d3e71fcdf)

[![Crates.io](https://img.shields.io/crates/v/binsleuth.svg)](https://crates.io/crates/binsleuth)
[![Downloads](https://img.shields.io/crates/d/binsleuth.svg)](https://crates.io/crates/binsleuth)
[![docs.rs](https://docs.rs/binsleuth/badge.svg)](https://docs.rs/binsleuth)
[![CI](https://github.com/long-910/BinSleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/long-910/BinSleuth/actions/workflows/ci.yml)
[![Release](https://github.com/long-910/BinSleuth/actions/workflows/release.yml/badge.svg)](https://github.com/long-910/BinSleuth/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Tests](https://img.shields.io/badge/tests-85%20passing-brightgreen.svg)](#)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/long-910?label=Sponsor&logo=githubsponsors&color=EA4AAA)](https://github.com/sponsors/long-910)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/long910)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/long-kudo.vscode-binsleuth?label=VS%20Code%20Extension&logo=visualstudiocode&logoColor=white&color=007ACC)](https://marketplace.visualstudio.com/items?itemName=long-kudo.vscode-binsleuth)

**Language / 言語 / 语言:**
[English](README.md) · [日本語](README.ja.md) · [中文](README.zh.md)

</div>

---

## What is BinSleuth?

BinSleuth is a **security-focused static binary analyzer** written in Rust.
It acts as a quick health-check for compiled executables — answering:

- *"Does this binary have modern security protections enabled?"*
- *"Could this section be packed or encrypted malware?"*
- *"Does this binary import dangerous OS-level functions?"*

It is designed for **security engineers, malware researchers, and developers** who need instant answers without launching a full reverse-engineering suite.

---

## Features

### 1. Security Hardening Checks

| Flag | Description | ELF | PE |
|------|-------------|-----|----|
| **NX** | Non-executable stack/data — prevents code injection | `PT_GNU_STACK` | `NX_COMPAT` |
| **PIE** | Position-Independent Executable — enables ASLR | `ET_DYN` | `DYNAMIC_BASE` |
| **RELRO** | Read-Only Relocations — prevents GOT overwrite | `PT_GNU_RELRO` + `BIND_NOW` | N/A |
| **Stack Canary** | Buffer-overflow tripwire symbol present | `__stack_chk_fail` | `__security_cookie` |
| **FORTIFY_SOURCE** | Fortified libc wrappers (`__*_chk`) — compile-time bounds checks on unsafe string/memory calls | `__memcpy_chk`, … | `__memcpy_chk`, … |
| **No RPATH/RUNPATH** | Absence of embedded library search paths — prevents library-injection via writable/relative RPATH | `DT_RPATH` / `DT_RUNPATH` | N/A |
| **Stripped** | Debug symbols / DWARF info absent — limits reverse-engineering | `.debug_*` sections | Debug directory |

Each check reports one of: **Enabled** / **Partial** / **Disabled** / **N/A**

### 2. Section Entropy Analysis

BinSleuth computes the [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) of every section:

```
H = -Σ P(x) · log₂(P(x))       range: [0.0 – 8.0]
```

| Entropy Range | Interpretation |
|---------------|----------------|
| 0.0 – 4.0 | Normal code / data |
| 4.0 – 7.0 | Compressed resources (normal) |
| **> 7.0** | **⚠ Packed / Encrypted — investigate** |

### 3. Dangerous Symbol Detection

BinSleuth flags symbols that commonly appear in malicious or insecure binaries, and reports each one with a **category**:

| Category | JSON value | Examples |
|----------|-----------|---------|
| **Code execution** | `exec` | `system`, `execve`, `popen`, `WinExec`, `CreateProcess` |
| **Network** | `net` | `connect`, `socket`, `gethostbyname`, `WinHttpOpen` |
| **Memory manipulation** | `mem` | `mprotect`, `mmap`, `VirtualAlloc`, `VirtualProtect` |

### 4. Security Score

Every report includes a numeric **security score from 0 to 100**, computed from the weighted hardening results:

| Check | Points |
|-------|--------|
| NX | 20 |
| PIE | 20 |
| RELRO (Full) | 15 · Partial: 7 · N/A: 15 |
| Stack Canary | 15 |
| FORTIFY_SOURCE | 10 |
| No RPATH/RUNPATH | 10 |
| Stripped | 5 |
| No dangerous symbols | 5 (−1 per symbol) |

---

## Installation

### From crates.io (recommended)

```bash
cargo install binsleuth
```

### From source

```bash
git clone https://github.com/long-910/BinSleuth.git
cd BinSleuth
cargo build --release
# Binary output: ./target/release/binsleuth
```

### Requirements

- Rust **1.85** or later
- No system libraries required — pure Rust

---

## VS Code Extension

BinSleuth is also available as a **Visual Studio Code extension**, providing an interactive GUI on top of the same analysis engine.

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/long-kudo.vscode-binsleuth?label=Install%20from%20Marketplace&logo=visualstudiocode&color=007ACC)](https://marketplace.visualstudio.com/items?itemName=long-kudo.vscode-binsleuth)

### Features

- **Section Map** — Doughnut chart showing each section's share of file size, color-coded by type (`.text` green, `.data` cyan, `.bss` purple). Click a slice to jump to that offset in the Hex Editor.
- **Section Heatmap** — Horizontal bar chart encoding size (bar length) and Shannon entropy (color: blue=low → red=high). Sections with entropy above 6.5 glow neon to flag potential packing or encryption. Sortable by offset, size, entropy, or name.
- **Security Flags Panel** — Color-coded badges for NX, PIE, RELRO, CANARY, FORTIFY, and STRIP, plus an overall **security score (0–100)**.
- **Dangerous Symbol Detection** — Lists high-risk imported symbols (shell execution, network I/O, memory manipulation).
- **Auto-Detection** — Analysis triggers automatically when a recognized binary file is opened.
- **Export** — Reports exportable as Markdown, JSON, or CSV.
- **Localization** — Japanese and Simplified Chinese supported.

### Installation

Search **"BinSleuth"** in the VS Code Extensions panel, or install via the Marketplace link above.

You can also download platform-specific VSIX packages from the [GitHub Releases](https://github.com/long-910/vscode-binsleuth/releases):

| Platform | File |
|----------|------|
| Linux | `*-linux-x64.vsix` |
| macOS (Apple Silicon) | `*-darwin-arm64.vsix` |
| macOS (Intel) | `*-darwin-x64.vsix` |
| Windows | `*-win32-x64.vsix` |

**Requirements:** VS Code >= 1.85. The [Hex Editor](https://marketplace.visualstudio.com/items?itemName=ms-vscode.hexeditor) extension is optional but enables click-to-offset navigation.

### Commands

| Command | Description |
|---------|-------------|
| `binsleuth.analyzeFile` | Analyze a file selected in the Explorer (right-click context menu) |
| `binsleuth.analyzeActiveFile` | Analyze the currently open file (editor title menu / command palette) |

> **Note:** The extension calls a local Rust subprocess (`binsleuth-bridge`) — no network calls or telemetry.

---

## Usage

```
binsleuth [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to the ELF or PE binary to analyze

Options:
  -v, --verbose  Show all sections, even those with normal entropy
      --json     Output results as JSON instead of the colored terminal report
      --strict   Exit with code 2 if any hardening protection is missing or
                 dangerous symbols are found (useful in CI pipelines)
  -h, --help     Print help
  -V, --version  Print version
```

### Basic analysis

```bash
binsleuth /usr/bin/ls
binsleuth ./myapp.exe
binsleuth ./suspicious_binary
```

### Show all sections (including low-entropy ones)

```bash
binsleuth --verbose /usr/bin/python3
```

### JSON output (for scripting / CI integration)

```bash
binsleuth --json /usr/bin/ls | jq '.hardening.nx'
```

### CI pipeline — fail if hardening issues are found

```bash
binsleuth --strict ./myapp && echo "Hardening OK" || echo "Hardening FAILED"
# Exit 0 = all good, Exit 2 = hardening issues found, Exit 1 = parse error
```

### Example output — hardened binary

```
╔══════════════════════════════════════════════════════╗
║              BinSleuth — Binary Analyzer             ║
╚══════════════════════════════════════════════════════╝

  File:    /usr/bin/ls
  Format:  ELF
  Arch:    X86_64

  ── Security Hardening ──────────────────────────────────

  [ ENABLED  ]  NX (Non-Executable Stack)
  [ ENABLED  ]  PIE (ASLR-compatible)
  [ ENABLED  ]  RELRO (Read-Only Relocations)
  [ ENABLED  ]  Stack Canary
  [ ENABLED  ]  FORTIFY_SOURCE
  [ ENABLED  ]  No RPATH/RUNPATH
  [ ENABLED  ]  Debug Symbols Stripped

  ── Section Entropy ─────────────────────────────────────

  Section                      Size (B)     Entropy  Status
  ──────────────────────────────────────────────────────────────────────
  All sections within normal entropy range.
  (run with --verbose to show all sections)

  ── Dangerous Symbol Usage ──────────────────────────────

  No dangerous symbols detected.

  ────────────────────────────────────────────────────────
  Analysis complete.
```

### Example output — suspicious / packed binary

```
  ── Section Entropy ─────────────────────────────────────

  Section                      Size (B)     Entropy  Status
  ──────────────────────────────────────────────────────────────────────
  UPX0                           491520       7.9981  ⚠  Packed/Encrypted suspected
  UPX1                            32768       7.9912  ⚠  Packed/Encrypted suspected

  2 section(s) with entropy > 7.0 detected!

  ── Dangerous Symbol Usage ──────────────────────────────

  3 dangerous symbol(s) found:
    ▶  execve    [exec]
    ▶  mprotect  [mem]
    ▶  socket    [net]
```

---

## Library Usage

`binsleuth` can be used as a Rust library crate in addition to the CLI — for example as the core analysis engine of a VS Code extension.

Add to your `Cargo.toml`:

```toml
[dependencies]
binsleuth = "0.4"
```

### Unified API (recommended)

```rust
// Single call — returns hardening, sections, and security score together
let data = std::fs::read("path/to/binary")?;
let report = binsleuth::analyze(&data)?;

println!("Score: {}/100", report.security_score);
println!("PIE:   {:?}", report.hardening.pie);

for sec in &report.sections {
    println!("{}: va={:#x} entropy={:.4} rwx={}{}{}",
        sec.name, sec.virtual_address, sec.entropy,
        if sec.permissions.read  { 'r' } else { '-' },
        if sec.permissions.write { 'w' } else { '-' },
        if sec.permissions.execute { 'x' } else { '-' },
    );
}

for sym in &report.hardening.dangerous_symbols {
    println!("  {:?}  {}", sym.category, sym.name);
}

// Serialize to JSON string (no stdout side-effect)
let json: String = report.to_json_pretty();
```

### Lower-level API

```rust
use binsleuth::analyzer::hardening::HardeningInfo;
use binsleuth::analyzer::entropy::SectionEntropy;

let hardening = HardeningInfo::analyze(&data)?;
let sections  = SectionEntropy::analyze(&data)?;
```

See the [API documentation on docs.rs](https://docs.rs/binsleuth) and [`examples/basic.rs`](examples/basic.rs) for a complete runnable example.

---

## Project Structure

```
BinSleuth/
├── Cargo.toml
├── README.md              ← English (default)
├── README.ja.md           ← Japanese
├── README.zh.md           ← Chinese (Simplified)
├── CHANGELOG.md
├── LICENSE
├── examples/
│   └── basic.rs           # Library usage example
└── src/
    ├── lib.rs             # Library crate root (public API)
    ├── main.rs            # CLI entry point (clap)
    ├── analyzer/
    │   ├── mod.rs
    │   ├── entropy.rs     # Shannon entropy + SectionEntropy
    │   └── hardening.rs   # NX / PIE / RELRO / Canary / symbols
    └── report/
        ├── mod.rs
        ├── terminal.rs    # Colored terminal renderer
        └── json.rs        # JSON output serializer
```

### Key types

| Type | Location | Role |
|------|----------|------|
| `AnalysisReport` | `analyzer/mod.rs` | Unified result: hardening + sections + security score |
| `HardeningInfo` | `analyzer/hardening.rs` | Aggregated hardening check results |
| `CheckResult` | `analyzer/hardening.rs` | `Enabled` / `Partial(msg)` / `Disabled` / `N/A` |
| `DangerousSymbol` | `analyzer/hardening.rs` | Symbol name + `SymbolCategory` (Exec / Net / Mem) |
| `SectionEntropy` | `analyzer/entropy.rs` | Section name, virtual address, file offset, size, entropy, permissions |
| `SectionPermissions` | `analyzer/entropy.rs` | `read`, `write`, `execute` bool flags |
| `TerminalReporter` | `report/terminal.rs` | Colored terminal output renderer |

---

## Supported Formats

| Format | Architectures | NX | PIE | RELRO | Canary | FORTIFY | RPATH |
|--------|---------------|----|-----|-------|--------|---------|-------|
| ELF 32-bit | x86, ARM, MIPS, … | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ELF 64-bit | x86-64, AArch64, … | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| PE 32-bit (PE32) | x86 | ✅ | ✅ | N/A | ✅ | ✅ | N/A |
| PE 64-bit (PE32+) | x86-64 | ✅ | ✅ | N/A | ✅ | ✅ | N/A |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Analysis completed successfully |
| `1` | File not found, parse error, or unsupported format |
| `2` | `--strict` mode: analysis succeeded but hardening issues were found |

---

## Testing

```bash
# All tests (unit + integration)
cargo test

# Unit tests only
cargo test --lib

# Integration tests only (requires compiled binary)
cargo test --test cli

# Lint
cargo clippy -- -D warnings

# Format check
cargo fmt --check
```

The test suite includes **56 unit tests**, **26 integration tests**, and **3 doc tests** (85 total):

| Module | Tests | Coverage |
|--------|-------|---------|
| `analyzer::entropy` | 17 | Shannon formula, edge cases, monotonicity, `extract_permissions` (ELF/COFF flags), section metadata |
| `analyzer::hardening` | 23 | PE header parsing, RELRO states, FORTIFY_SOURCE, RPATH, ELF self-analysis, dangerous symbol categorization |
| `analyzer` (mod) | 16 | `compute_score` boundary values and per-check deductions, `AnalysisReport` API, JSON serialization |
| `tests::cli` | 26 | CLI flags, JSON output, strict mode, stripped detection, error handling, `security_score`, section metadata, dangerous symbol categories |
| doc tests | 3 | Library API smoke tests |

---

## Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Write tests where applicable
4. Run `cargo test && cargo clippy -- -D warnings` before submitting
5. Open a Pull Request

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details *(coming soon)*.

---

## Roadmap

- [x] JSON output mode (`--json`)
- [x] DWARF / PDB debug-info / stripped detection
- [x] Strict mode for CI pipelines (`--strict`, exit code 2)
- [x] FORTIFY_SOURCE detection (`__*_chk` symbol scan)
- [x] RPATH/RUNPATH detection (library-injection risk)
- [x] Library API — `AnalysisReport::analyze()` unified entry point
- [x] Security score (0–100) for dashboard/badge display
- [x] Per-section virtual address, file offset, and rwx permissions
- [x] Dangerous symbol categories (Exec / Net / Mem) for colour-coded visualisation
- [x] VS Code extension — [vscode-binsleuth](https://marketplace.visualstudio.com/items?itemName=long-kudo.vscode-binsleuth) (visualisation front-end)
- [ ] SARIF output format
- [ ] macOS Mach-O support
- [ ] Import table diff between two binaries (`binsleuth diff a.out b.out`)
- [ ] Yara-rule-style byte-pattern matching

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [object](https://crates.io/crates/object) — cross-platform binary parsing
- [clap](https://crates.io/crates/clap) — CLI argument parsing
- [anyhow](https://crates.io/crates/anyhow) — ergonomic error handling
- [colored](https://crates.io/crates/colored) — terminal color output

---

<div align="center">
Made with ❤️ and Rust
</div>
