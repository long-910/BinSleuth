use colored::Colorize;
use std::path::Path;

use crate::analyzer::entropy::SectionEntropy;
use crate::analyzer::hardening::{CheckResult, HardeningInfo};

/// Entropy threshold above which a section is considered packed/encrypted.
const ENTROPY_WARN_THRESHOLD: f64 = 7.0;

pub struct TerminalReporter {
    verbose: bool,
}

impl TerminalReporter {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    pub fn print_report(
        &self,
        path: &Path,
        hardening: &HardeningInfo,
        entropies: &[SectionEntropy],
    ) {
        self.print_header(path, hardening);
        self.print_hardening(hardening);
        self.print_entropy(entropies);
        self.print_dangerous_symbols(hardening);
        self.print_footer();
    }

    // ── Header ────────────────────────────────────────────────────────────────

    fn print_header(&self, path: &Path, hardening: &HardeningInfo) {
        println!();
        println!(
            "{}",
            "╔══════════════════════════════════════════════════════╗"
                .cyan()
                .bold()
        );
        println!(
            "{}",
            "║              BinSleuth — Binary Analyzer             ║"
                .cyan()
                .bold()
        );
        println!(
            "{}",
            "╚══════════════════════════════════════════════════════╝"
                .cyan()
                .bold()
        );
        println!();
        println!(
            "  {}  {}",
            "File:".bold(),
            path.display().to_string().yellow()
        );
        println!("  {}  {}", "Format:".bold(), hardening.format.yellow());
        println!("  {}  {}", "Arch:".bold(), hardening.architecture.yellow());
        println!();
    }

    // ── Hardening section ─────────────────────────────────────────────────────

    fn print_hardening(&self, info: &HardeningInfo) {
        println!(
            "{}",
            "  ── Security Hardening ──────────────────────────────────".bold()
        );
        println!();

        self.print_check("NX (Non-Executable Stack)", &info.nx);
        self.print_check("PIE (ASLR-compatible)", &info.pie);
        self.print_check("RELRO (Read-Only Relocations)", &info.relro);
        self.print_check("Stack Canary", &info.stack_canary);

        println!();
    }

    fn print_check(&self, label: &str, result: &CheckResult) {
        let (badge, color_fn): (&str, fn(&str) -> colored::ColoredString) = match result {
            CheckResult::Enabled => (" ENABLED  ", |s| s.green().bold()),
            CheckResult::Partial(_) => (" PARTIAL  ", |s| s.yellow().bold()),
            CheckResult::Disabled => (" DISABLED ", |s| s.red().bold()),
            CheckResult::NotApplicable => ("   N/A    ", |s| s.dimmed()),
        };

        let badge_str = color_fn(&format!("[{}]", badge));

        match result {
            CheckResult::Partial(note) => {
                println!("  {}  {:40}  {}", badge_str, label, note.dimmed());
            }
            _ => {
                println!("  {}  {}", badge_str, label);
            }
        }
    }

    // ── Entropy section ───────────────────────────────────────────────────────

    fn print_entropy(&self, entropies: &[SectionEntropy]) {
        println!(
            "{}",
            "  ── Section Entropy ─────────────────────────────────────".bold()
        );
        println!();
        println!(
            "  {:<24} {:>12}  {:>10}  {}",
            "Section".bold(),
            "Size (B)".bold(),
            "Entropy".bold(),
            "Status".bold()
        );
        println!("  {}", "─".repeat(70).dimmed());

        for sec in entropies {
            let is_high = sec.entropy > ENTROPY_WARN_THRESHOLD;

            if !is_high && !self.verbose {
                continue;
            }

            let entropy_str = format!("{:.4}", sec.entropy);
            let (entropy_colored, status) = if is_high {
                (
                    entropy_str.red().bold(),
                    "⚠  Packed/Encrypted suspected".red().bold().to_string(),
                )
            } else {
                (entropy_str.green(), "OK".green().to_string())
            };

            println!(
                "  {:<24} {:>12}  {:>10}  {}",
                sec.name.yellow(),
                sec.size,
                entropy_colored,
                status,
            );
        }

        // Always show a summary of high-entropy sections
        let high_count = entropies
            .iter()
            .filter(|s| s.entropy > ENTROPY_WARN_THRESHOLD)
            .count();
        if high_count == 0 {
            println!("  {}", "All sections within normal entropy range.".green());
        } else {
            println!();
            println!(
                "  {}",
                format!(
                    "{} section(s) with entropy > {ENTROPY_WARN_THRESHOLD:.1} detected!",
                    high_count
                )
                .red()
                .bold()
            );
        }

        if !self.verbose
            && entropies
                .iter()
                .all(|s| s.entropy <= ENTROPY_WARN_THRESHOLD)
        {
            println!("  {}", "(run with --verbose to show all sections)".dimmed());
        }

        println!();
    }

    // ── Dangerous symbols section ─────────────────────────────────────────────

    fn print_dangerous_symbols(&self, info: &HardeningInfo) {
        println!(
            "{}",
            "  ── Dangerous Symbol Usage ──────────────────────────────".bold()
        );
        println!();

        if info.dangerous_symbols.is_empty() {
            println!("  {}", "No dangerous symbols detected.".green());
        } else {
            println!(
                "  {}",
                format!(
                    "{} dangerous symbol(s) found:",
                    info.dangerous_symbols.len()
                )
                .red()
                .bold()
            );
            for sym in &info.dangerous_symbols {
                println!("    {}  {}", "▶".red(), sym.yellow());
            }
        }

        println!();
    }

    // ── Footer ────────────────────────────────────────────────────────────────

    fn print_footer(&self) {
        println!(
            "{}",
            "  ────────────────────────────────────────────────────────".dimmed()
        );
        println!("  {}", "Analysis complete.".dimmed());
        println!();
    }
}
