use serde::Serialize;
use std::path::Path;

use crate::analyzer::entropy::SectionEntropy;
use crate::analyzer::hardening::HardeningInfo;
use crate::analyzer::AnalysisReport;

/// Full JSON report emitted by the CLI (includes the file path).
#[derive(Serialize)]
struct JsonReport<'a> {
    file: String,
    security_score: u8,
    hardening: &'a HardeningInfo,
    sections: &'a [SectionEntropy],
}

/// Serialize the analysis results as pretty-printed JSON to stdout.
pub fn print_json(path: &Path, report: &AnalysisReport) {
    let output = JsonReport {
        file: path.display().to_string(),
        security_score: report.security_score,
        hardening: &report.hardening,
        sections: &report.sections,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("JSON serialization cannot fail")
    );
}
