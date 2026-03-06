<div align="center">

# 🔍 BinSleuth

**A fast, zero-dependency CLI tool for static binary security analysis.**
Inspect ELF & PE binaries for hardening flags and detect packed/encrypted sections — in milliseconds.

[![Crates.io](https://img.shields.io/crates/v/binsleuth.svg)](https://crates.io/crates/binsleuth)
[![docs.rs](https://docs.rs/binsleuth/badge.svg)](https://docs.rs/binsleuth)
[![CI](https://github.com/long-910/BinSleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/long-910/BinSleuth/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

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

BinSleuth flags symbols that commonly appear in malicious or insecure binaries:

| Category | Examples |
|----------|---------|
| **Code execution** | `system`, `execve`, `popen`, `WinExec`, `CreateProcess` |
| **Network** | `connect`, `socket`, `gethostbyname`, `WinHttpOpen` |
| **Memory manipulation** | `mprotect`, `mmap`, `VirtualAlloc`, `VirtualProtect` |

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

- Rust **1.70** or later
- No system libraries required — pure Rust

---

## Usage

```
binsleuth [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to the ELF or PE binary to analyze

Options:
  -v, --verbose  Show all sections, even those with normal entropy
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
    ▶  execve
    ▶  mprotect
    ▶  socket
```

---

## Project Structure

```
BinSleuth/
├── Cargo.toml
├── README.md           ← English (default)
├── README.ja.md        ← Japanese
├── README.zh.md        ← Chinese (Simplified)
├── LICENSE
└── src/
    ├── main.rs                  # CLI entry point (clap)
    ├── analyzer/
    │   ├── mod.rs
    │   ├── entropy.rs           # Shannon entropy + SectionEntropy
    │   └── hardening.rs         # NX / PIE / RELRO / Canary / symbols
    └── report/
        ├── mod.rs
        └── terminal.rs          # Colored terminal renderer
```

### Key types

| Type | Location | Role |
|------|----------|------|
| `HardeningInfo` | `analyzer/hardening.rs` | Aggregated hardening check results |
| `CheckResult` | `analyzer/hardening.rs` | `Enabled` / `Partial(msg)` / `Disabled` / `N/A` |
| `SectionEntropy` | `analyzer/entropy.rs` | Section name + entropy value + byte size |
| `TerminalReporter` | `report/terminal.rs` | Colored terminal output renderer |

---

## Supported Formats

| Format | Architectures | NX | PIE | RELRO | Canary |
|--------|---------------|----|-----|-------|--------|
| ELF 32-bit | x86, ARM, MIPS, … | ✅ | ✅ | ✅ | ✅ |
| ELF 64-bit | x86-64, AArch64, … | ✅ | ✅ | ✅ | ✅ |
| PE 32-bit (PE32) | x86 | ✅ | ✅ | N/A | ✅ |
| PE 64-bit (PE32+) | x86-64 | ✅ | ✅ | N/A | ✅ |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Analysis completed successfully |
| `1` | File not found, parse error, or unsupported format |

---

## Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Write tests where applicable
4. Run `cargo test && cargo clippy` before submitting
5. Open a Pull Request

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details *(coming soon)*.

---

## Roadmap

- [ ] JSON / SARIF output mode (`--output json`)
- [ ] macOS Mach-O support
- [ ] Import table diff between two binaries (`binsleuth diff a.out b.out`)
- [ ] DWARF / PDB debug-info presence detection
- [ ] Yara-rule-style byte-pattern matching
- [ ] GitHub Actions CI badge & automated crates.io release

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
