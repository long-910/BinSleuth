//! # BinSleuth
//!
//! Binary inspection and security analysis toolkit for ELF and PE binaries.
//!
//! BinSleuth detects:
//! - Security hardening flags (NX, PIE, RELRO, Stack Canary, FORTIFY_SOURCE, RPATH/RUNPATH, debug-symbol stripping)
//! - Shannon entropy per section (detects packing/encryption)
//! - Dangerous symbol usage (`system()`, `execve()`, `mprotect()`, …)
//!
//! ## Library Usage
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
//! let entropies = SectionEntropy::analyze(&data).unwrap();
//! for sec in &entropies {
//!     println!("{}: entropy={:.4}", sec.name, sec.entropy);
//! }
//! ```
//!
//! ## CLI
//!
//! Install and use the `binsleuth` binary directly:
//!
//! ```text
//! cargo install binsleuth
//! binsleuth ./target/debug/binsleuth
//! binsleuth --json ./mybinary
//! binsleuth --strict --verbose ./mybinary
//! ```

pub mod analyzer;
pub mod report;
