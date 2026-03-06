mod analyzer;
mod report;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

use analyzer::{entropy::SectionEntropy, hardening::HardeningInfo};
use report::terminal::TerminalReporter;

/// BinSleuth — ELF/PE binary security analyzer
#[derive(Parser, Debug)]
#[command(
    name = "binsleuth",
    version,
    about = "Analyze ELF/PE binaries for security hardening flags and entropy anomalies",
    long_about = "BinSleuth inspects compiled binaries for:\n\
                  • Security hardening flags (NX, PIE, RELRO, Stack Canary)\n\
                  • Shannon entropy per section (detects packing/encryption)\n\
                  • Dangerous symbol usage (system(), execve(), mprotect(), …)"
)]
struct Cli {
    /// Path to the ELF or PE binary to analyze
    #[arg(value_name = "FILE")]
    path: PathBuf,

    /// Show all sections, even those with normal entropy
    #[arg(short, long)]
    verbose: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}: {}", "error".red().bold(), e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let path = &cli.path;
    if !path.exists() {
        anyhow::bail!(
            "File not found: '{}'\nPlease provide a valid path to an ELF or PE binary.",
            path.display()
        );
    }

    let data = fs::read(path)
        .with_context(|| format!("Failed to read file: '{}'", path.display()))?;

    if data.is_empty() {
        anyhow::bail!("File '{}' is empty.", path.display());
    }

    // ── Hardening analysis ──────────────────────────────────────────────────
    let hardening = HardeningInfo::analyze(&data).with_context(|| {
        format!(
            "Failed to parse '{}'. Is it a valid ELF or PE binary?",
            path.display()
        )
    })?;

    // ── Entropy analysis ────────────────────────────────────────────────────
    let entropies = SectionEntropy::analyze(&data)
        .with_context(|| format!("Failed to compute section entropies for '{}'", path.display()))?;

    // ── Report ──────────────────────────────────────────────────────────────
    let reporter = TerminalReporter::new(cli.verbose);
    reporter.print_report(path, &hardening, &entropies);

    Ok(())
}
