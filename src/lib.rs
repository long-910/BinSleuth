//! # BinSleuth
//!
//! Binary inspection and security analysis toolkit for ELF and PE binaries.
//!
//! BinSleuth detects:
//! - Security hardening flags (NX, PIE, RELRO, Stack Canary, FORTIFY_SOURCE, RPATH/RUNPATH, debug-symbol stripping)
//! - Shannon entropy per section (detects packing/encryption)
//! - Dangerous symbol usage (`system()`, `execve()`, `mprotect()`, …) with category (Exec / Net / Mem)
//! - Per-section virtual address, file offset, and read/write/execute permissions
//!
//! ## Quick start (library)
//!
//! ```no_run
//! let data = std::fs::read("path/to/binary").unwrap();
//!
//! // Single call — returns everything including security score
//! let report = binsleuth::analyze(&data).unwrap();
//! println!("Score: {}/100", report.security_score);
//! println!("{}", report.to_json_pretty());
//! ```
//!
//! ## Lower-level API
//!
//! ```no_run
//! use binsleuth::analyzer::hardening::HardeningInfo;
//! use binsleuth::analyzer::entropy::SectionEntropy;
//!
//! let data = std::fs::read("path/to/binary").unwrap();
//!
//! let hardening = HardeningInfo::analyze(&data).unwrap();
//! println!("PIE: {:?}", hardening.pie);
//!
//! let sections = SectionEntropy::analyze(&data).unwrap();
//! for sec in &sections {
//!     println!("{}: va={:#x} entropy={:.4} r={} w={} x={}",
//!         sec.name, sec.virtual_address, sec.entropy,
//!         sec.permissions.read, sec.permissions.write, sec.permissions.execute);
//! }
//! ```
//!
//! ## CLI
//!
//! ```text
//! cargo install binsleuth
//! binsleuth ./target/debug/binsleuth
//! binsleuth --json ./mybinary
//! binsleuth --strict --verbose ./mybinary
//! ```

pub mod analyzer;
pub mod report;

pub use analyzer::AnalysisReport;

/// Convenience wrapper: analyze raw binary bytes and return a complete [`AnalysisReport`].
///
/// Equivalent to [`AnalysisReport::analyze`].
pub fn analyze(data: &[u8]) -> anyhow::Result<AnalysisReport> {
    AnalysisReport::analyze(data)
}
