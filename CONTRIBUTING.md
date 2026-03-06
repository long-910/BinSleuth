# Contributing to BinSleuth

Thank you for your interest in contributing!
This document explains how to set up your environment, submit changes, and get them merged.

---

## Table of Contents

1. [Development Environment](#development-environment)
2. [Project Structure](#project-structure)
3. [Making Changes](#making-changes)
4. [Code Style](#code-style)
5. [Tests](#tests)
6. [Submitting a Pull Request](#submitting-a-pull-request)
7. [Reporting Issues](#reporting-issues)

---

## Development Environment

### Prerequisites

| Tool | Minimum version | Notes |
|------|----------------|-------|
| Rust | 1.85 (MSRV) | Install via [rustup](https://rustup.rs/) |
| rustfmt | bundled with stable | `rustup component add rustfmt` |
| clippy | bundled with stable | `rustup component add clippy` |

### Getting Started

```bash
git clone https://github.com/long-910/BinSleuth.git
cd BinSleuth
cargo build
cargo test
```

---

## Project Structure

```
BinSleuth/
├── src/
│   ├── main.rs               # CLI entry point (clap)
│   └── analyzer/
│       ├── mod.rs            # Public analyzer API
│       ├── hardening.rs      # ELF / PE hardening checks
│       └── entropy.rs        # Section-level Shannon entropy
├── tests/
│   └── cli.rs                # Integration tests (black-box CLI)
├── .github/workflows/
│   ├── ci.yml                # fmt → clippy → test → build → MSRV
│   └── release.yml           # crates.io publish on tag push
├── Cargo.toml
└── CHANGELOG.md
```

---

## Making Changes

1. **Fork** the repository and create a feature branch from `main`:

   ```bash
   git checkout -b feat/your-feature
   ```

2. **Make your changes** in small, focused commits.

3. **Update `CHANGELOG.md`** under the `[Unreleased]` section using the
   [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format:
   - `Added` – new features
   - `Changed` – changes to existing behaviour
   - `Deprecated` – features that will be removed
   - `Removed` – removed features
   - `Fixed` – bug fixes
   - `Security` – vulnerability fixes

4. **Open a Pull Request** against the `main` branch.

---

## Code Style

All code must pass the CI checks before merging:

```bash
# Format
cargo fmt --all

# Lint (warnings are treated as errors in CI)
cargo clippy --all-targets --all-features -- -D warnings
```

Additional guidelines:

- Follow standard Rust idioms (prefer `?` over `unwrap`, use iterators, etc.).
- Keep public items documented with `///` doc comments.
- Do not introduce `unsafe` code without a clear justification in the PR description.
- Rust edition **2024** is in use — take advantage of its improvements.

---

## Tests

```bash
# All unit tests
cargo test --lib

# Integration tests (CLI black-box)
cargo test --test cli

# All tests at once
cargo test
```

When adding a new feature, please add corresponding tests:

- **Unit tests** live in the same file as the code under `#[cfg(test)]`.
- **Integration tests** go in `tests/cli.rs` and exercise the compiled binary.

CI runs tests on **Ubuntu, macOS, and Windows** — please avoid platform-specific assumptions.

---

## Submitting a Pull Request

- Keep the PR focused: one logical change per PR.
- Write a clear title and description explaining the *why*, not just the *what*.
- Reference any related issues with `Closes #123` or `Fixes #123`.
- All CI checks (fmt, clippy, tests, MSRV) must be green before review.
- A maintainer will review and merge after approval.

---

## Reporting Issues

Please use [GitHub Issues](https://github.com/long-910/BinSleuth/issues) and include:

- BinSleuth version (`binsleuth --version`)
- OS and architecture
- Steps to reproduce
- Expected vs actual behaviour

---

*By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).*
