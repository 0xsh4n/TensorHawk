//! Baseline suppression (v0.2).
//!
//! A baseline is a set of finding fingerprints that have already been triaged
//! and accepted. Passing `--baseline known.json` suppresses those findings so
//! CI only fails on *new* issues — the standard way to adopt a scanner on a
//! codebase that already has known, accepted noise.

use crate::report::Report;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// A persisted set of accepted finding fingerprints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub fingerprints: HashSet<String>,
}

impl Baseline {
    /// Load a baseline from a JSON file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Build a baseline capturing every finding currently in `reports`.
    pub fn from_reports(reports: &[Report]) -> Self {
        let mut fingerprints = HashSet::new();
        for r in reports {
            for f in &r.findings {
                fingerprints.insert(f.fingerprint());
            }
        }
        Baseline { fingerprints }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn contains(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }

    /// Drop baselined findings from a report in place, returning how many were
    /// suppressed. Summary counts and the risk score are recomputed.
    pub fn apply(&self, report: &mut Report) -> usize {
        let before = report.findings.len();
        let kept: Vec<_> = std::mem::take(&mut report.findings)
            .into_iter()
            .filter(|f| !self.contains(&f.fingerprint()))
            .collect();
        let suppressed = before - kept.len();
        *report = Report::new(
            report.target.clone(),
            report.format.clone(),
            report.bytes,
            kept,
        );
        suppressed
    }
}
