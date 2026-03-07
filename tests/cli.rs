//! Integration tests — exercise the `binsleuth` CLI as a child process.
//!
//! Cargo automatically compiles the binary before running tests in `tests/`,
//! so `env!("CARGO_BIN_EXE_binsleuth")` always points to a fresh build.

use std::process::Command;

// ── Helper ────────────────────────────────────────────────────────────────────

fn binsleuth() -> Command {
    Command::new(env!("CARGO_BIN_EXE_binsleuth"))
}

// ── Basic CLI behaviour ───────────────────────────────────────────────────────

#[test]
fn help_exits_zero_and_mentions_project() {
    let out = binsleuth().arg("--help").output().unwrap();
    assert!(out.status.success(), "exit code: {:?}", out.status.code());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("BinSleuth") || stdout.contains("binsleuth"),
        "expected project name in --help output"
    );
}

#[test]
fn version_exits_zero_and_contains_semver() {
    let out = binsleuth().arg("--version").output().unwrap();
    assert!(out.status.success(), "exit code: {:?}", out.status.code());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Expect something like "binsleuth 0.1.0"
    assert!(
        stdout.contains("binsleuth"),
        "expected binary name in --version output"
    );
    // Very loose semver check: at least one digit separated by a dot
    assert!(
        stdout.chars().any(|c| c.is_ascii_digit()),
        "expected version number in --version output"
    );
}

#[test]
fn no_args_exits_nonzero() {
    let out = binsleuth().output().unwrap();
    assert!(
        !out.status.success(),
        "expected non-zero exit when no FILE is given"
    );
}

// ── Error handling ────────────────────────────────────────────────────────────

#[test]
fn missing_file_exits_with_code_1() {
    let out = binsleuth()
        .arg("/this/path/does/not/exist/binsleuth_test_missing")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error") || stderr.contains("Error"),
        "expected an error message on stderr"
    );
}

#[test]
fn non_binary_file_exits_with_code_1() {
    // Write a plain-text file and try to analyze it
    let tmp = std::env::temp_dir().join("binsleuth_text_test.txt");
    std::fs::write(&tmp, b"hello, this is not a binary\n").unwrap();
    let out = binsleuth().arg(&tmp).output().unwrap();
    std::fs::remove_file(&tmp).ok();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn empty_file_exits_with_code_1() {
    let tmp = std::env::temp_dir().join("binsleuth_empty_test.bin");
    std::fs::write(&tmp, b"").unwrap();
    let out = binsleuth().arg(&tmp).output().unwrap();
    std::fs::remove_file(&tmp).ok();
    assert_eq!(out.status.code(), Some(1));
}

// ── Self-analysis (Linux / ELF) ───────────────────────────────────────────────

/// Analyze the binsleuth binary itself — valid ELF (Linux) or PE (Windows).
#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn self_analysis_exits_zero() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg(bin).output().unwrap();
    assert!(
        out.status.success(),
        "self-analysis failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn self_analysis_stdout_contains_sections() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg(bin).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Every successful report should include these section headers
    assert!(
        stdout.contains("Security Hardening"),
        "missing hardening section"
    );
    assert!(
        stdout.contains("Section Entropy"),
        "missing entropy section"
    );
    assert!(
        stdout.contains("Dangerous Symbol"),
        "missing symbol section"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn self_analysis_reports_elf() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg(bin).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ELF"), "expected ELF format on Linux");
}

#[test]
#[cfg(target_os = "windows")]
fn self_analysis_reports_pe() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg(bin).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PE"), "expected PE format on Windows");
}

// ── JSON output ───────────────────────────────────────────────────────────────

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn json_flag_exits_zero() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg("--json").arg(bin).output().unwrap();
    assert!(
        out.status.success(),
        "exit code: {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn json_output_is_valid_json() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg("--json").arg(bin).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("--json output must be valid JSON");
}

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn json_output_contains_expected_keys() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg("--json").arg(bin).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v.get("file").is_some(), "missing 'file' key");
    assert!(v.get("hardening").is_some(), "missing 'hardening' key");
    assert!(v.get("sections").is_some(), "missing 'sections' key");
}

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn json_hardening_contains_expected_fields() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg("--json").arg(bin).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let h = &v["hardening"];
    for field in &["nx", "pie", "relro", "stack_canary", "stripped", "format", "architecture"] {
        assert!(h.get(field).is_some(), "missing hardening field '{field}'");
    }
}

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn json_and_verbose_can_coexist() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth()
        .arg("--json")
        .arg("--verbose")
        .arg(bin)
        .output()
        .unwrap();
    assert!(out.status.success(), "exit code: {:?}", out.status.code());
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("output must still be valid JSON with --verbose");
}

// ── Strict mode ───────────────────────────────────────────────────────────────

#[test]
fn strict_flag_is_accepted() {
    // --strict on a missing file should still produce exit code 1 (file error), not "unknown flag"
    let out = binsleuth()
        .arg("--strict")
        .arg("/nonexistent/binary")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit code 1 for missing file, not unknown-flag error"
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn strict_flag_exits_zero_or_two_for_self() {
    // Self-analysis with --strict: exit must be 0 (all protections present)
    // or 2 (some protection missing) — never 1 (parse error).
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg("--strict").arg(bin).output().unwrap();
    let code = out.status.code().unwrap_or(99);
    assert!(
        code == 0 || code == 2,
        "expected exit code 0 or 2 for self-analysis with --strict, got {code}"
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn strict_and_json_flags_together() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth()
        .arg("--strict")
        .arg("--json")
        .arg(bin)
        .output()
        .unwrap();
    let code = out.status.code().unwrap_or(99);
    // Exit 0 (all good) or 2 (strict issues) — output must be valid JSON either way
    assert!(code == 0 || code == 2, "unexpected exit code {code}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str::<serde_json::Value>(&stdout)
        .expect("output must be valid JSON even with --strict");
}

// ── Stripped field ─────────────────────────────────────────────────────────────

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn json_stripped_field_is_valid_value() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg("--json").arg(bin).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let stripped = v["hardening"]["stripped"].as_str().unwrap_or("");
    assert!(
        stripped == "enabled" || stripped == "disabled",
        "stripped must be 'enabled' or 'disabled', got '{stripped}'"
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn terminal_output_contains_stripped_check() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");
    let out = binsleuth().arg(bin).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Stripped"),
        "expected 'Stripped' in terminal output"
    );
}

/// With --verbose, all sections must appear (not just high-entropy ones).
#[test]
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn verbose_flag_produces_more_output() {
    let bin = env!("CARGO_BIN_EXE_binsleuth");

    let normal = binsleuth().arg(bin).output().unwrap();
    let verbose = binsleuth().arg("--verbose").arg(bin).output().unwrap();

    assert!(normal.status.success());
    assert!(verbose.status.success());

    // Verbose output should be at least as long as normal output
    assert!(
        verbose.stdout.len() >= normal.stdout.len(),
        "verbose output should not be shorter than default output"
    );
}
