//! Basic example: analyze a binary and print hardening + entropy results.
//!
//! Run with:
//! ```text
//! cargo run --example basic -- ./target/debug/binsleuth
//! ```

use binsleuth::analyzer::entropy::SectionEntropy;
use binsleuth::analyzer::hardening::HardeningInfo;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: basic <path-to-binary>");
        std::process::exit(1);
    });

    let data = std::fs::read(&path).expect("Failed to read file");

    // ── Hardening checks ────────────────────────────────────────────────────
    let hardening = HardeningInfo::analyze(&data).expect("Failed to analyze binary");

    println!("=== Hardening: {} ({}) ===", path, hardening.format);
    println!("  Architecture: {}", hardening.architecture);
    println!("  NX:           {:?}", hardening.nx);
    println!("  PIE:          {:?}", hardening.pie);
    println!("  RELRO:        {:?}", hardening.relro);
    println!("  Stack Canary: {:?}", hardening.stack_canary);
    println!("  Stripped:     {:?}", hardening.stripped);

    if !hardening.dangerous_symbols.is_empty() {
        println!("  Dangerous symbols: {:?}", hardening.dangerous_symbols);
    }

    // ── Section entropy ─────────────────────────────────────────────────────
    let entropies = SectionEntropy::analyze(&data).expect("Failed to compute entropy");

    println!("\n=== Section Entropy ===");
    for sec in &entropies {
        let flag = if sec.entropy > 7.0 { " ⚠ HIGH" } else { "" };
        println!(
            "  {:<24}  entropy={:.4}  size={}{}",
            sec.name, sec.entropy, sec.size, flag
        );
    }
}
