<div align="center">

# 🔍 BinSleuth

**快速、零依赖的静态二进制安全分析 CLI 工具。**
毫秒级检测 ELF 和 PE 文件的安全加固配置与加密/混淆特征。

[![Crates.io](https://img.shields.io/crates/v/binsleuth.svg)](https://crates.io/crates/binsleuth)
[![docs.rs](https://docs.rs/binsleuth/badge.svg)](https://docs.rs/binsleuth)
[![CI](https://github.com/long-910/BinSleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/long-910/BinSleuth/actions/workflows/ci.yml)
[![Release](https://github.com/long-910/BinSleuth/actions/workflows/release.yml/badge.svg)](https://github.com/long-910/BinSleuth/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![Tests](https://img.shields.io/badge/tests-32%20passing-brightgreen.svg)](#)

**Language / 言語 / 语言:**
[English](README.md) · [日本語](README.ja.md) · [中文](README.zh.md)

</div>

---

## BinSleuth 是什么？

BinSleuth 是一款用 **Rust 编写的安全导向静态二进制分析工具**。
它就像一份编译后可执行文件的"安全体检报告"，快速回答以下问题：

- *"这个二进制文件是否启用了现代安全防护措施？"*
- *"某个节区是否可能是被加壳或加密的恶意代码？"*
- *"这个二进制文件是否导入了危险的操作系统级函数？"*

专为**安全工程师、恶意软件研究人员和开发者**设计，无需启动完整的逆向工程套件，即可在命令行中即时获得答案。

---

## 功能特性

### 1. 安全加固配置检测

| 标志 | 说明 | ELF | PE |
|------|------|-----|----|
| **NX** | 将栈/数据区标为不可执行，防止代码注入 | `PT_GNU_STACK` | `NX_COMPAT` |
| **PIE** | 位置无关可执行文件 — 启用 ASLR 地址随机化 | `ET_DYN` | `DYNAMIC_BASE` |
| **RELRO** | 重定位表只读化 — 防止 GOT 覆盖攻击 | `PT_GNU_RELRO` + `BIND_NOW` | N/A |
| **Stack Canary** | 检测缓冲区溢出保护符号是否存在 | `__stack_chk_fail` | `__security_cookie` |

每项检测结果为以下之一：**Enabled（已启用）** / **Partial（部分启用）** / **Disabled（未启用）** / **N/A（不适用）**

### 2. 节区熵值分析

BinSleuth 对每个节区计算 [香农熵](https://zh.wikipedia.org/wiki/%E7%86%B5_(%E4%BF%A1%E6%81%AF%E8%AE%BA))：

```
H = -Σ P(x) · log₂(P(x))       取值范围: [0.0 – 8.0]
```

| 熵值范围 | 解读 |
|---------|------|
| 0.0 – 4.0 | 正常代码 / 数据 |
| 4.0 – 7.0 | 压缩资源（正常） |
| **> 7.0** | **⚠ 疑似加壳 / 加密 — 需进一步调查** |

### 3. 危险符号检测

BinSleuth 标记常见于恶意或不安全二进制文件中的符号：

| 类别 | 示例 |
|------|------|
| **代码执行** | `system`, `execve`, `popen`, `WinExec`, `CreateProcess` |
| **网络操作** | `connect`, `socket`, `gethostbyname`, `WinHttpOpen` |
| **内存操作** | `mprotect`, `mmap`, `VirtualAlloc`, `VirtualProtect` |

---

## 安装

### 从 crates.io 安装（推荐）

```bash
cargo install binsleuth
```

### 从源码构建

```bash
git clone https://github.com/long-910/BinSleuth.git
cd BinSleuth
cargo build --release
# 二进制文件输出路径: ./target/release/binsleuth
```

### 环境要求

- Rust **1.70** 或更高版本
- 无需系统库 — 纯 Rust 实现

---

## 使用方法

```
binsleuth [OPTIONS] <FILE>

参数:
  <FILE>  待分析的 ELF 或 PE 二进制文件路径

选项:
  -v, --verbose  显示所有节区，包括熵值正常的节区
  -h, --help     显示帮助信息
  -V, --version  显示版本号
```

### 基本分析

```bash
binsleuth /usr/bin/ls
binsleuth ./myapp.exe
binsleuth ./suspicious_binary
```

### 显示所有节区（包括低熵节区）

```bash
binsleuth --verbose /usr/bin/python3
```

### 示例输出 — 安全加固的二进制文件

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

### 示例输出 — 可疑 / 加壳的二进制文件

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

## 项目结构

```
BinSleuth/
├── Cargo.toml
├── README.md           ← 英文（默认）
├── README.ja.md        ← 日文
├── README.zh.md        ← 中文（简体）
├── LICENSE
└── src/
    ├── main.rs                  # CLI 入口（clap）
    ├── analyzer/
    │   ├── mod.rs
    │   ├── entropy.rs           # 香农熵 + SectionEntropy
    │   └── hardening.rs         # NX / PIE / RELRO / Canary / 符号检测
    └── report/
        ├── mod.rs
        └── terminal.rs          # 彩色终端输出渲染
```

### 核心类型

| 类型 | 文件 | 作用 |
|------|------|------|
| `HardeningInfo` | `analyzer/hardening.rs` | 汇总所有加固检测结果 |
| `CheckResult` | `analyzer/hardening.rs` | `Enabled` / `Partial(msg)` / `Disabled` / `N/A` |
| `SectionEntropy` | `analyzer/entropy.rs` | 节区名称 + 熵值 + 字节大小 |
| `TerminalReporter` | `report/terminal.rs` | 彩色终端输出渲染器 |

---

## 支持的格式

| 格式 | 架构 | NX | PIE | RELRO | Canary |
|------|------|----|-----|-------|--------|
| ELF 32-bit | x86, ARM, MIPS … | ✅ | ✅ | ✅ | ✅ |
| ELF 64-bit | x86-64, AArch64 … | ✅ | ✅ | ✅ | ✅ |
| PE 32-bit (PE32) | x86 | ✅ | ✅ | N/A | ✅ |
| PE 64-bit (PE32+) | x86-64 | ✅ | ✅ | N/A | ✅ |

---

## 退出码

| 代码 | 含义 |
|------|------|
| `0` | 分析成功完成 |
| `1` | 文件未找到 / 解析错误 / 不支持的格式 |

---

## 测试

```bash
# 运行所有测试（单元测试 + 集成测试）
cargo test

# 仅运行单元测试
cargo test --lib

# 仅运行集成测试（需要编译好的二进制文件）
cargo test --test cli

# 代码检查
cargo clippy -- -D warnings

# 格式检查
cargo fmt --check
```

测试套件包含 **22 个单元测试** 和 **10 个集成测试**：

| 模块 | 测试数量 | 覆盖范围 |
|------|---------|---------|
| `analyzer::entropy` | 9 | 香农公式、边界值、单调性 |
| `analyzer::hardening` | 13 | PE 头解析、RELRO 状态、ELF 自分析 |
| `tests::cli` | 10 | CLI 参数、错误处理、自分析、详细模式 |

---

## 参与贡献

欢迎贡献代码！

1. Fork 本仓库
2. 创建功能分支：`git checkout -b feat/your-feature`
3. 适当添加测试
4. 提交前运行 `cargo test && cargo clippy -- -D warnings`
5. 发起 Pull Request

详情请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)（*即将发布*）。

---

## 开发路线图

- [ ] JSON / SARIF 输出模式（`--output json`）
- [ ] macOS Mach-O 格式支持
- [ ] 两个二进制文件的导入表差异对比（`binsleuth diff a.out b.out`）
- [ ] DWARF / PDB 调试信息检测
- [ ] Yara 风格的字节模式匹配
- [ ] GitHub Actions CI 及 crates.io 自动发布

---

## 许可证

本项目采用 **MIT 许可证** — 详情请参阅 [LICENSE](LICENSE)。

---

## 致谢

- [object](https://crates.io/crates/object) — 跨平台二进制解析
- [clap](https://crates.io/crates/clap) — CLI 参数解析
- [anyhow](https://crates.io/crates/anyhow) — 错误处理
- [colored](https://crates.io/crates/colored) — 终端彩色输出

---

<div align="center">
用 ❤️ 和 Rust 打造
</div>
