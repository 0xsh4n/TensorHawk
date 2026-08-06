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
//!
//! For finer control — user rule packs, experimental detectors, or scanning
//! many files in parallel — see [`ScanConfig`], [`analyze_with_config`], and
//! [`analyze_paths`].

pub mod artifact;
pub mod baseline;
pub mod finding;
pub mod format;
pub(crate) mod pb;
pub mod report;
pub mod rules;
pub mod scanners;

use anyhow::Result;
use rayon::prelude::*;
use std::path::{Path, PathBuf};

pub use artifact::Artifact;
pub use baseline::Baseline;
pub use finding::{Finding, Severity};
pub use report::Report;

/// Configuration for a scan: which optional scanners and rule packs to enable.
#[derive(Debug, Default, Clone)]
pub struct ScanConfig {
    /// Directory of user `*.model_rule` packs to load in addition to built-ins.
    pub user_rules: Option<PathBuf>,
    /// Enable the experimental, heuristic research detectors (v2.0).
    pub experimental: bool,
}

/// Analyze a single artifact with the default built-in scanner set.
pub fn analyze(path: &Path) -> Result<Report> {
    analyze_with_config(path, &ScanConfig::default())
}

/// Analyze a single artifact with an explicit scanner set (for custom/community
/// plugin selection).
pub fn analyze_with(path: &Path, scanners: &[Box<dyn scanners::Scanner>]) -> Result<Report> {
    let artifact = Artifact::load(path)?;

    // Scanners are pure functions of the artifact, so we can fan them out.
    let findings: Vec<Finding> = scanners
        .par_iter()
        .flat_map(|scanner| scanner.scan(&artifact))
        .collect();

    Ok(Report::new(
        path.display().to_string(),
        artifact.format.as_str().to_string(),
        artifact.size,
        findings,
    ))
}

/// Analyze a single artifact, assembling the scanner set from `config`.
pub fn analyze_with_config(path: &Path, config: &ScanConfig) -> Result<Report> {
    let scanners = build_scanners(config)?;
    analyze_with(path, &scanners)
}

/// Analyze many artifacts in parallel, preserving input order. Each result is
/// independent; one bad file never fails the batch.
pub fn analyze_paths(paths: &[PathBuf], config: &ScanConfig) -> Vec<(PathBuf, Result<Report>)> {
    // Build the scanner set once; it is shared read-only across threads.
    let scanners = match build_scanners(config) {
        Ok(s) => s,
        Err(e) => {
            // Surface the config error against every path rather than panicking.
            return paths
                .iter()
                .map(|p| (p.clone(), Err(anyhow::anyhow!("{e}"))))
                .collect();
        }
    };
    paths
        .par_iter()
        .map(|path| {
            let res = Artifact::load(path).map(|artifact| {
                let findings: Vec<Finding> = scanners
                    .par_iter()
                    .flat_map(|s| s.scan(&artifact))
                    .collect();
                Report::new(
                    path.display().to_string(),
                    artifact.format.as_str().to_string(),
                    artifact.size,
                    findings,
                )
            });
            (path.clone(), res)
        })
        .collect()
}

/// Assemble the scanner set for a configuration: built-ins, then any user rule
/// packs, then experimental detectors if enabled.
pub fn build_scanners(config: &ScanConfig) -> Result<Vec<Box<dyn scanners::Scanner>>> {
    let mut set = scanners::builtin_scanners();

    if let Some(dir) = &config.user_rules {
        let rules = rules::load_dir(dir).map_err(|e| anyhow::anyhow!(e))?;
        if !rules.is_empty() {
            set.push(Box::new(rules::RuleScanner::new(rules, "user-rules")));
        }
    }

    if config.experimental {
        set.extend(scanners::experimental::experimental_scanners());
    }

    Ok(set)
}
