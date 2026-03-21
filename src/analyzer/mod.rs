pub mod entropy;
pub mod hardening;

use anyhow::Result;
use serde::Serialize;

use crate::analyzer::entropy::SectionEntropy;
use crate::analyzer::hardening::{CheckResult, HardeningInfo};

/// Unified analysis result returned by [`AnalysisReport::analyze`].
///
/// This is the primary type for library consumers (e.g. a VS Code extension).
/// It bundles the hardening checks, per-section entropy/metadata, and an
/// aggregate security score into a single serialisable struct.
///
/// # Example
/// ```no_run
/// let data = std::fs::read("mybinary").unwrap();
/// let report = binsleuth::AnalysisReport::analyze(&data).unwrap();
/// println!("score: {}", report.security_score);
/// println!("{}", report.to_json_pretty());
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    /// Hardening-flag results (NX, PIE, RELRO, …)
    pub hardening: HardeningInfo,
    /// Per-section entropy, virtual address, file offset, and permissions
    pub sections: Vec<SectionEntropy>,
    /// Aggregate security score in [0, 100]
    pub security_score: u8,
}

impl AnalysisReport {
    /// Analyze raw binary bytes and produce a complete `AnalysisReport`.
    pub fn analyze(data: &[u8]) -> Result<Self> {
        let hardening = HardeningInfo::analyze(data)?;
        let sections = SectionEntropy::analyze(data)?;
        let security_score = compute_score(&hardening, &sections);
        Ok(Self {
            hardening,
            sections,
            security_score,
        })
    }

    /// Serialize to compact JSON (no trailing newline).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("JSON serialization cannot fail")
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("JSON serialization cannot fail")
    }
}

// ── Security score ─────────────────────────────────────────────────────────────
//
// Point budget (total = 100):
//   NX                20
//   PIE               20
//   RELRO             15  (Partial RELRO = 7; N/A counts as full — PE doesn't have RELRO)
//   Stack canary      15
//   FORTIFY_SOURCE    10
//   No RPATH          10  (N/A = static binary = safe)
//   Stripped           5
//   No dangerous syms  5  (−1 per symbol, floor 0)

fn compute_score(info: &HardeningInfo, _sections: &[SectionEntropy]) -> u8 {
    let mut score: i32 = 0;

    score += match &info.nx {
        CheckResult::Enabled => 20,
        CheckResult::Partial(_) => 10,
        _ => 0,
    };

    score += match &info.pie {
        CheckResult::Enabled => 20,
        CheckResult::Partial(_) => 10,
        _ => 0,
    };

    score += match &info.relro {
        CheckResult::Enabled => 15,
        CheckResult::Partial(_) => 7,
        CheckResult::NotApplicable => 15, // PE doesn't use RELRO — not a fault
        CheckResult::Disabled => 0,
    };

    score += match &info.stack_canary {
        CheckResult::Enabled => 15,
        CheckResult::Partial(_) => 7,
        _ => 0,
    };

    score += match &info.fortify_source {
        CheckResult::Enabled => 10,
        CheckResult::Partial(_) => 5,
        _ => 0,
    };

    score += match &info.rpath {
        CheckResult::Enabled => 10,       // no RPATH/RUNPATH — safe
        CheckResult::NotApplicable => 10, // static binary — safe
        CheckResult::Partial(_) => 5,
        CheckResult::Disabled => 0,
    };

    score += match &info.stripped {
        CheckResult::Enabled => 5,
        _ => 0,
    };

    // Dangerous symbols: start at 5, deduct 1 per symbol (floor 0)
    let sym_deduction = (info.dangerous_symbols.len() as i32).min(5);
    score += 5 - sym_deduction;

    score.clamp(0, 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::hardening::{DangerousSymbol, SymbolCategory};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn full_hardening() -> HardeningInfo {
        HardeningInfo {
            format: "ELF".to_owned(),
            architecture: "X86_64".to_owned(),
            nx: CheckResult::Enabled,
            pie: CheckResult::Enabled,
            relro: CheckResult::Enabled,
            stack_canary: CheckResult::Enabled,
            fortify_source: CheckResult::Enabled,
            rpath: CheckResult::Enabled,
            stripped: CheckResult::Enabled,
            dangerous_symbols: vec![],
        }
    }

    fn bare_hardening() -> HardeningInfo {
        HardeningInfo {
            format: "ELF".to_owned(),
            architecture: "X86".to_owned(),
            nx: CheckResult::Disabled,
            pie: CheckResult::Disabled,
            relro: CheckResult::Disabled,
            stack_canary: CheckResult::Disabled,
            fortify_source: CheckResult::Disabled,
            rpath: CheckResult::Disabled,
            stripped: CheckResult::Disabled,
            dangerous_symbols: vec![],
        }
    }

    fn dangerous(name: &str, cat: SymbolCategory) -> DangerousSymbol {
        DangerousSymbol {
            name: name.to_owned(),
            category: cat,
        }
    }

    // ── compute_score ─────────────────────────────────────────────────────────

    #[test]
    fn score_100_for_fully_hardened() {
        assert_eq!(compute_score(&full_hardening(), &[]), 100);
    }

    #[test]
    fn score_5_for_all_disabled_no_dangerous_symbols() {
        // All protections disabled, but no dangerous symbols → 5 pts (clean symbol table)
        assert_eq!(compute_score(&bare_hardening(), &[]), 5);
    }

    #[test]
    fn score_0_for_all_disabled_with_dangerous_symbols() {
        let mut info = bare_hardening();
        info.dangerous_symbols = (0..5)
            .map(|i| dangerous(&format!("sym{i}"), SymbolCategory::Exec))
            .collect();
        assert_eq!(compute_score(&info, &[]), 0);
    }

    #[test]
    fn score_na_relro_does_not_penalise() {
        // PE binaries have RELRO = NotApplicable; must not count against score
        let mut info = full_hardening();
        info.relro = CheckResult::NotApplicable;
        assert_eq!(compute_score(&info, &[]), 100);
    }

    #[test]
    fn score_na_rpath_does_not_penalise() {
        // Static binaries have no dynamic segment; rpath = NotApplicable must not penalise
        let mut info = full_hardening();
        info.rpath = CheckResult::NotApplicable;
        assert_eq!(compute_score(&info, &[]), 100);
    }

    #[test]
    fn score_partial_relro_deducts_correctly() {
        let mut info = full_hardening();
        info.relro = CheckResult::Partial("Partial RELRO".to_owned());
        // Full RELRO = 15 pts, Partial = 7 pts
        assert_eq!(compute_score(&info, &[]), 100 - (15 - 7));
    }

    #[test]
    fn score_one_dangerous_symbol_deducts_one() {
        let mut info = full_hardening();
        info.dangerous_symbols = vec![dangerous("system", SymbolCategory::Exec)];
        assert_eq!(compute_score(&info, &[]), 99);
    }

    #[test]
    fn score_dangerous_symbols_capped_at_five() {
        let mut info = full_hardening();
        info.dangerous_symbols = (0..10)
            .map(|i| dangerous(&format!("sym{i}"), SymbolCategory::Net))
            .collect();
        // Max deduction for symbols is 5
        assert_eq!(compute_score(&info, &[]), 95);
    }

    #[test]
    fn score_always_clamped_to_zero() {
        // All disabled + excess dangerous symbols must never go negative
        let mut info = bare_hardening();
        info.dangerous_symbols = (0..20)
            .map(|i| dangerous(&format!("sym{i}"), SymbolCategory::Mem))
            .collect();
        assert_eq!(compute_score(&info, &[]), 0);
    }

    #[test]
    fn score_is_additive_per_check() {
        // Disable one check at a time and verify the deduction is exactly right
        let full = compute_score(&full_hardening(), &[]);

        let mut no_nx = full_hardening();
        no_nx.nx = CheckResult::Disabled;
        assert_eq!(compute_score(&no_nx, &[]), full - 20, "NX is worth 20 pts");

        let mut no_pie = full_hardening();
        no_pie.pie = CheckResult::Disabled;
        assert_eq!(compute_score(&no_pie, &[]), full - 20, "PIE is worth 20 pts");

        let mut no_relro = full_hardening();
        no_relro.relro = CheckResult::Disabled;
        assert_eq!(compute_score(&no_relro, &[]), full - 15, "RELRO is worth 15 pts");

        let mut no_canary = full_hardening();
        no_canary.stack_canary = CheckResult::Disabled;
        assert_eq!(compute_score(&no_canary, &[]), full - 15, "Stack canary is worth 15 pts");

        let mut no_fortify = full_hardening();
        no_fortify.fortify_source = CheckResult::Disabled;
        assert_eq!(compute_score(&no_fortify, &[]), full - 10, "FORTIFY_SOURCE is worth 10 pts");

        let mut has_rpath = full_hardening();
        has_rpath.rpath = CheckResult::Disabled;
        assert_eq!(compute_score(&has_rpath, &[]), full - 10, "No-RPATH is worth 10 pts");

        let mut not_stripped = full_hardening();
        not_stripped.stripped = CheckResult::Disabled;
        assert_eq!(compute_score(&not_stripped, &[]), full - 5, "Stripped is worth 5 pts");
    }

    // ── AnalysisReport API ────────────────────────────────────────────────────

    #[test]
    #[cfg(target_os = "linux")]
    fn analyze_self_succeeds() {
        let path = std::env::current_exe().expect("current exe");
        let data = std::fs::read(&path).expect("read self");
        let report = AnalysisReport::analyze(&data).expect("analyze");

        assert!(!report.sections.is_empty(), "expected at least one section");
        assert!(
            report.security_score <= 100,
            "score {} is out of [0, 100]",
            report.security_score
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn to_json_is_valid_and_has_expected_keys() {
        let path = std::env::current_exe().expect("current exe");
        let data = std::fs::read(&path).expect("read self");
        let report = AnalysisReport::analyze(&data).expect("analyze");

        let v: serde_json::Value =
            serde_json::from_str(&report.to_json()).expect("to_json must produce valid JSON");
        assert!(v.get("hardening").is_some(), "missing 'hardening'");
        assert!(v.get("sections").is_some(), "missing 'sections'");
        assert!(v.get("security_score").is_some(), "missing 'security_score'");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn to_json_pretty_is_valid_json() {
        let path = std::env::current_exe().expect("current exe");
        let data = std::fs::read(&path).expect("read self");
        let report = AnalysisReport::analyze(&data).expect("analyze");

        serde_json::from_str::<serde_json::Value>(&report.to_json_pretty())
            .expect("to_json_pretty must produce valid JSON");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn to_json_score_matches_struct_field() {
        let path = std::env::current_exe().expect("current exe");
        let data = std::fs::read(&path).expect("read self");
        let report = AnalysisReport::analyze(&data).expect("analyze");

        let v: serde_json::Value = serde_json::from_str(&report.to_json()).unwrap();
        let json_score = v["security_score"].as_u64().unwrap() as u8;
        assert_eq!(json_score, report.security_score);
    }

    #[test]
    fn analyze_rejects_empty_data() {
        assert!(AnalysisReport::analyze(&[]).is_err());
    }

    #[test]
    fn analyze_rejects_non_binary() {
        assert!(AnalysisReport::analyze(b"hello, not a binary").is_err());
    }
}
