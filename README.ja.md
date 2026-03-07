<div align="center">

# 🔍 BinSleuth

**ELF/PE バイナリのセキュリティ設定検証とエントロピー解析を行う、高速 Rust 製 CLI ツール。**
インストール不要の依存ゼロ設計。ミリ秒単位で解析結果を返します。

[![Crates.io](https://img.shields.io/crates/v/binsleuth.svg)](https://crates.io/crates/binsleuth)
[![docs.rs](https://docs.rs/binsleuth/badge.svg)](https://docs.rs/binsleuth)
[![CI](https://github.com/long-910/BinSleuth/actions/workflows/ci.yml/badge.svg)](https://github.com/long-910/BinSleuth/actions/workflows/ci.yml)
[![Release](https://github.com/long-910/BinSleuth/actions/workflows/release.yml/badge.svg)](https://github.com/long-910/BinSleuth/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Tests](https://img.shields.io/badge/tests-42%20passing-brightgreen.svg)](#)

**Language / 言語 / 语言:**
[English](README.md) · [日本語](README.ja.md) · [中文](README.zh.md)

</div>

---

## BinSleuth とは？

BinSleuth は **Rust 製のセキュリティ特化型静的バイナリ解析ツール**です。
コンパイル済み実行ファイルの「セキュリティ健康診断」として、以下の問いに即答します。

- *「このバイナリは現代的なセキュリティ保護が有効になっているか？」*
- *「このセクションはパック・暗号化されたマルウェアの可能性があるか？」*
- *「危険な OS レベル関数をインポートしていないか？」*

大規模なリバースエンジニアリングスイートを起動することなく、**セキュリティエンジニア・マルウェア研究者・開発者**がコマンドラインから即座に答えを得られるよう設計されています。

---

## 機能

### 1. セキュリティ・ハーデニングチェック

| フラグ | 説明 | ELF | PE |
|--------|------|-----|----|
| **NX** | スタック/データ領域を実行不可にしてコードインジェクションを防止 | `PT_GNU_STACK` | `NX_COMPAT` |
| **PIE** | 位置独立実行形式 — ASLR によるアドレスランダム化を有効化 | `ET_DYN` | `DYNAMIC_BASE` |
| **RELRO** | 再配置テーブルの読み取り専用化 — GOT 上書き攻撃を防止 | `PT_GNU_RELRO` + `BIND_NOW` | N/A |
| **Stack Canary** | バッファオーバーフロー検知シンボルの有無 | `__stack_chk_fail` | `__security_cookie` |
| **Stripped** | デバッグシンボル / DWARF 情報の除去 — リバースエンジニアリングを困難に | `.debug_*` セクション | デバッグディレクトリ |

各チェックは **Enabled（有効）** / **Partial（部分的）** / **Disabled（無効）** / **N/A** のいずれかで報告されます。

### 2. セクション・エントロピー解析

各セクションの [シャノンエントロピー](https://ja.wikipedia.org/wiki/%E6%83%85%E5%A0%B1%E3%82%A8%E3%83%B3%E3%83%88%E3%83%AD%E3%83%94%E3%83%BC) を計算します。

```
H = -Σ P(x) · log₂(P(x))       範囲: [0.0 – 8.0]
```

| エントロピー範囲 | 解釈 |
|----------------|------|
| 0.0 – 4.0 | 通常のコード / データ |
| 4.0 – 7.0 | 圧縮リソース（正常範囲） |
| **> 7.0** | **⚠ パック / 暗号化の疑い — 要調査** |

### 3. 危険シンボル検出

マルウェアや脆弱なバイナリに頻出するシンボルをフラグします。

| カテゴリ | 例 |
|---------|---|
| **コード実行** | `system`, `execve`, `popen`, `WinExec`, `CreateProcess` |
| **ネットワーク** | `connect`, `socket`, `gethostbyname`, `WinHttpOpen` |
| **メモリ操作** | `mprotect`, `mmap`, `VirtualAlloc`, `VirtualProtect` |

---

## インストール

### crates.io から（推奨）

```bash
cargo install binsleuth
```

### ソースからビルド

```bash
git clone https://github.com/long-910/BinSleuth.git
cd BinSleuth
cargo build --release
# バイナリ出力先: ./target/release/binsleuth
```

### 要件

- Rust **1.85** 以降
- システムライブラリ不要 — 純粋 Rust 実装

---

## 使い方

```
binsleuth [OPTIONS] <FILE>

引数:
  <FILE>  解析対象の ELF または PE バイナリのパス

オプション:
  -v, --verbose  エントロピーが正常なセクションも含めてすべて表示
      --json     カラーターミナル出力の代わりに JSON 形式で出力
      --strict   ハーデニング保護が欠如しているか危険シンボルが検出された場合に終了コード 2 で終了
                 （CI パイプラインで有用）
  -h, --help     ヘルプを表示
  -V, --version  バージョンを表示
```

### 基本的な解析

```bash
binsleuth /usr/bin/ls
binsleuth ./myapp.exe
binsleuth ./suspicious_binary
```

### 全セクション表示（低エントロピーセクションも含む）

```bash
binsleuth --verbose /usr/bin/python3
```

### JSON 出力（スクリプト / CI 連携）

```bash
binsleuth --json /usr/bin/ls | jq '.hardening.nx'
```

### CI パイプライン — ハーデニング問題があれば失敗させる

```bash
binsleuth --strict ./myapp && echo "Hardening OK" || echo "Hardening FAILED"
# 終了コード 0 = 正常、2 = ハーデニング問題あり、1 = パースエラー
```

### 出力例 — ハーデニング済みバイナリ

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

### 出力例 — 疑わしい / パック済みバイナリ

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

## プロジェクト構成

```
BinSleuth/
├── Cargo.toml
├── README.md           ← 英語（デフォルト）
├── README.ja.md        ← 日本語
├── README.zh.md        ← 中国語（簡体字）
├── LICENSE
└── src/
    ├── main.rs                  # CLI エントリーポイント（clap）
    ├── analyzer/
    │   ├── mod.rs
    │   ├── entropy.rs           # シャノンエントロピー + SectionEntropy
    │   └── hardening.rs         # NX / PIE / RELRO / Canary / シンボル
    └── report/
        ├── mod.rs
        └── terminal.rs          # カラーターミナル出力
```

### 主要な型

| 型 | ファイル | 役割 |
|----|---------|------|
| `HardeningInfo` | `analyzer/hardening.rs` | ハーデニングチェック結果の集約 |
| `CheckResult` | `analyzer/hardening.rs` | `Enabled` / `Partial(msg)` / `Disabled` / `N/A` |
| `SectionEntropy` | `analyzer/entropy.rs` | セクション名 + エントロピー値 + バイトサイズ |
| `TerminalReporter` | `report/terminal.rs` | カラーターミナルレンダラー |

---

## 対応フォーマット

| フォーマット | アーキテクチャ | NX | PIE | RELRO | Canary |
|------------|-------------|----|-----|-------|--------|
| ELF 32-bit | x86, ARM, MIPS … | ✅ | ✅ | ✅ | ✅ |
| ELF 64-bit | x86-64, AArch64 … | ✅ | ✅ | ✅ | ✅ |
| PE 32-bit (PE32) | x86 | ✅ | ✅ | N/A | ✅ |
| PE 64-bit (PE32+) | x86-64 | ✅ | ✅ | N/A | ✅ |

---

## 終了コード

| コード | 意味 |
|--------|------|
| `0` | 解析正常終了 |
| `1` | ファイルが見つからない / パースエラー / 非対応フォーマット |
| `2` | `--strict` モード: 解析成功だがハーデニング問題を検出 |

---

## テスト

```bash
# 全テスト（ユニット + 統合）
cargo test

# ユニットテストのみ
cargo test --lib

# 統合テストのみ（ビルド済みバイナリが必要）
cargo test --test cli

# Lint
cargo clippy -- -D warnings

# フォーマットチェック
cargo fmt --check
```

テストスイートは **ユニットテスト 22 件** と **統合テスト 20 件** で構成されています。

| モジュール | テスト数 | カバー範囲 |
|-----------|---------|-----------|
| `analyzer::entropy` | 9 | シャノン公式、境界値、単調性 |
| `analyzer::hardening` | 13 | PE ヘッダー解析、RELRO 状態、ELF 自己解析 |
| `tests::cli` | 20 | CLI フラグ、JSON 出力、strict モード、stripped 検出、エラー処理 |

---

## コントリビュート

コントリビューションを歓迎します！

1. リポジトリをフォーク
2. フィーチャーブランチを作成: `git checkout -b feat/your-feature`
3. 必要に応じてテストを記述
4. `cargo test && cargo clippy -- -D warnings` でチェック
5. Pull Request を作成

詳細は [CONTRIBUTING.md](CONTRIBUTING.md) *(準備中)* をご覧ください。

---

## ロードマップ

- [x] JSON 出力モード（`--json`）
- [x] DWARF / PDB デバッグ情報 / stripped 検出
- [x] CI 向け strict モード（`--strict`、終了コード 2）
- [ ] SARIF 出力フォーマット
- [ ] macOS Mach-O 対応
- [ ] 2つのバイナリのインポート差分（`binsleuth diff a.out b.out`）
- [ ] Yara スタイルのバイトパターンマッチング

---

## ライセンス

MIT ライセンスのもとで公開されています。詳細は [LICENSE](LICENSE) をご覧ください。

---

## 謝辞

- [object](https://crates.io/crates/object) — クロスプラットフォームバイナリ解析
- [clap](https://crates.io/crates/clap) — CLI 引数パーサー
- [anyhow](https://crates.io/crates/anyhow) — エラーハンドリング
- [colored](https://crates.io/crates/colored) — ターミナルカラー出力

---

<div align="center">
❤️ と Rust で作られています
</div>
