//! Basic example: analyze a binary with the unified `AnalysisReport` API.
//!
//! Run with:
//! ```text
//! cargo run --example basic -- ./target/debug/binsleuth
//! ```

use binsleuth::AnalysisReport;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: basic <path-to-binary>");
        std::process::exit(1);
    });

    let data = std::fs::read(&path).expect("Failed to read file");

    // ── Single call returns everything ──────────────────────────────────────
    let report = AnalysisReport::analyze(&data).expect("Failed to analyze binary");
    let h = &report.hardening;

    println!("=== {} ({}, {}) ===", path, h.format, h.architecture);
    println!("  Security score: {}/100", report.security_score);
    println!();
    println!("=== Hardening ===");
    println!("  NX:             {:?}", h.nx);
    println!("  PIE:            {:?}", h.pie);
    println!("  RELRO:          {:?}", h.relro);
    println!("  Stack Canary:   {:?}", h.stack_canary);
    println!("  FORTIFY_SOURCE: {:?}", h.fortify_source);
    println!("  No RPATH:       {:?}", h.rpath);
    println!("  Stripped:       {:?}", h.stripped);

    if !h.dangerous_symbols.is_empty() {
        println!();
        println!("  Dangerous symbols ({}):", h.dangerous_symbols.len());
        for sym in &h.dangerous_symbols {
            println!("    {:?}  {}", sym.category, sym.name);
        }
    }

    // ── Section entropy with metadata ────────────────────────────────────────
    println!();
    println!("=== Sections ===");
    println!(
        "  {:<24}  {:>10}  {:>10}  {:>7}  rwx",
        "Name", "VA", "FileOff", "Entropy"
    );
    for sec in &report.sections {
        let p = &sec.permissions;
        let rwx = format!(
            "{}{}{}",
            if p.read { 'r' } else { '-' },
            if p.write { 'w' } else { '-' },
            if p.execute { 'x' } else { '-' },
        );
        let flag = if sec.entropy > 7.0 { " ⚠ HIGH" } else { "" };
        println!(
            "  {:<24}  {:#010x}  {:#010x}  {:.4}  {}{}",
            sec.name, sec.virtual_address, sec.file_offset, sec.entropy, rwx, flag
        );
    }

    // ── JSON output (for tool integration) ───────────────────────────────────
    // println!("{}", report.to_json_pretty());
}
