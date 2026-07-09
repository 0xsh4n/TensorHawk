//! Report assembly, aggregate risk scoring, and output rendering.

use crate::finding::{Finding, Severity};
use serde::{Deserialize, Serialize};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub target: String,
    pub format: String,
    pub bytes: u64,
    /// 0..=100 aggregate risk score.
    pub risk_score: u32,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl Report {
    pub fn new(target: String, format: String, bytes: u64, mut findings: Vec<Finding>) -> Self {
        // Highest severity, then highest confidence first.
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
        });

        let mut summary = Summary::default();
        let mut raw = 0f64;
        for f in &findings {
            match f.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
            raw += f.severity.weight() as f64 * f.confidence as f64;
        }
        // Squash into 0..=100 with diminishing returns so a single critical is
        // already alarming but many lows don't max it out artificially.
        let risk_score = (100.0 * (1.0 - (-raw / 16.0).exp())).round() as u32;

        Report {
            tool: "tensorhawk",
            tool_version: VERSION,
            target,
            format,
            bytes,
            risk_score: risk_score.min(100),
            summary,
            findings,
        }
    }

    pub fn worst(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Minimal but valid SARIF 2.1.0, suitable for GitHub code scanning.
    pub fn to_sarif(&self) -> String {
        let results: Vec<serde_json::Value> = self
            .findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "ruleId": f.rule_id,
                    "level": f.severity.sarif_level(),
                    "message": { "text": format!("{}: {}", f.title, f.detail) },
                    "properties": {
                        "scanner": f.scanner,
                        "confidence": f.confidence,
                        "severity": f.severity.as_str(),
                        "references": f.references,
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": self.target },
                            "logicalLocations": [{ "name": f.location.component }],
                        }
                    }],
                })
            })
            .collect();

        let doc = serde_json::json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": {
                    "name": "TensorHawk",
                    "informationUri": "https://github.com/your-org/tensorhawk",
                    "version": VERSION,
                    "rules": [],
                }},
                "results": results,
            }],
        });
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    }

    /// Human-readable terminal report with ANSI colour.
    pub fn to_human(&self, color: bool) -> String {
        let c = Palette::new(color);
        let mut out = String::new();
        out.push_str(&format!(
            "\n{}TensorHawk{} v{}  —  {}\n",
            c.bold, c.reset, VERSION, self.target
        ));
        out.push_str(&format!(
            "  format: {}   size: {}   risk score: {}{}/100{}\n\n",
            self.format,
            human_bytes(self.bytes),
            c.score(self.risk_score),
            self.risk_score,
            c.reset
        ));

        if self.findings.is_empty() {
            out.push_str(&format!("  {}✓ no findings{}\n", c.green, c.reset));
            return out;
        }

        for f in &self.findings {
            let tag = c.sev(f.severity);
            out.push_str(&format!(
                "  {}{:>8}{}  {}  {}({:.0}% conf){}\n",
                tag,
                f.severity.as_str().to_uppercase(),
                c.reset,
                f.title,
                c.dim,
                f.confidence * 100.0,
                c.reset
            ));
            out.push_str(&format!(
                "           {}{} · {} · {}{}\n",
                c.dim, f.rule_id, f.scanner, f.location.component, c.reset
            ));
            if let Some(ev) = &f.evidence {
                out.push_str(&format!("           {}evidence: {}{}\n", c.dim, ev, c.reset));
            }
        }

        out.push_str(&format!(
            "\n  {}{} critical  {}{} high  {}{} medium  {}{} low  {}{} info{}\n",
            c.red, self.summary.critical,
            c.magenta, self.summary.high,
            c.yellow, self.summary.medium,
            c.blue, self.summary.low,
            c.dim, self.summary.info,
            c.reset
        ));
        out
    }
}

fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

struct Palette {
    bold: &'static str,
    dim: &'static str,
    reset: &'static str,
    red: &'static str,
    magenta: &'static str,
    yellow: &'static str,
    blue: &'static str,
    green: &'static str,
}

impl Palette {
    fn new(color: bool) -> Self {
        if color {
            Palette {
                bold: "\x1b[1m",
                dim: "\x1b[2m",
                reset: "\x1b[0m",
                red: "\x1b[31m",
                magenta: "\x1b[35m",
                yellow: "\x1b[33m",
                blue: "\x1b[34m",
                green: "\x1b[32m",
            }
        } else {
            Palette {
                bold: "",
                dim: "",
                reset: "",
                red: "",
                magenta: "",
                yellow: "",
                blue: "",
                green: "",
            }
        }
    }
    fn sev(&self, s: Severity) -> &'static str {
        match s {
            Severity::Critical => self.red,
            Severity::High => self.magenta,
            Severity::Medium => self.yellow,
            Severity::Low => self.blue,
            Severity::Info => self.dim,
        }
    }
    fn score(&self, s: u32) -> &'static str {
        match s {
            0..=19 => self.green,
            20..=59 => self.yellow,
            _ => self.red,
        }
    }
}
