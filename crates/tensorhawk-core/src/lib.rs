//! TensorHawk core — static security analysis for LLM model artifacts.
//!
//! The public entrypoint is [`analyze`], which loads an artifact, runs the
//! registered scanners, and returns a scored [`Report`]. The CLI and any SDK
//! bindings are thin layers over this function.
//!
//! ```no_run
//! let report = tensorhawk_core::analyze(std::path::Path::new("model.bin")).unwrap();
//! println!("risk score: {}", report.risk_score);
//! ```

pub mod artifact;
pub mod finding;
pub mod format;
pub mod report;
pub mod scanners;

use anyhow::Result;
use std::path::Path;

pub use artifact::Artifact;
pub use finding::{Finding, Severity};
pub use report::Report;

/// Analyze a single artifact with the default built-in scanner set.
pub fn analyze(path: &Path) -> Result<Report> {
    analyze_with(path, &scanners::builtin_scanners())
}

/// Analyze a single artifact with an explicit scanner set (for custom/community
/// plugin selection).
pub fn analyze_with(path: &Path, scanners: &[Box<dyn scanners::Scanner>]) -> Result<Report> {
    let artifact = Artifact::load(path)?;

    let mut findings = Vec::new();
    for scanner in scanners {
        findings.extend(scanner.scan(&artifact));
    }

    Ok(Report::new(
        path.display().to_string(),
        artifact.format.as_str().to_string(),
        artifact.size,
        findings,
    ))
}
