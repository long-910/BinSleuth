use serde::Serialize;
use std::path::Path;

use crate::analyzer::entropy::SectionEntropy;
use crate::analyzer::hardening::HardeningInfo;

#[derive(Serialize)]
struct JsonReport<'a> {
    file: String,
    hardening: &'a HardeningInfo,
    sections: &'a [SectionEntropy],
}

/// Serialize the analysis results as pretty-printed JSON to stdout.
pub fn print_json(path: &Path, hardening: &HardeningInfo, entropies: &[SectionEntropy]) {
    let report = JsonReport {
        file: path.display().to_string(),
        hardening,
        sections: entropies,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("JSON serialization cannot fail")
    );
}
