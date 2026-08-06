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
            b.severity.cmp(&a.severity).then(
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
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
                    "informationUri": "https://github.com/0xsh4n/TensorHawk",
                    "version": VERSION,
                    "rules": [],
                }},
                "results": results,
            }],
        });
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    }

    /// A single-file HTML report fragment (the `<section>` for this artifact).
    fn to_html_section(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "<section class=\"report\">\n<h2>{}</h2>\n<p class=\"meta\">format <code>{}</code> · \
             size {} · risk score <span class=\"score score-{}\">{}/100</span></p>\n",
            esc(&self.target),
            esc(&self.format),
            human_bytes(self.bytes),
            score_class(self.risk_score),
            self.risk_score,
        ));
        out.push_str(&format!(
            "<p class=\"summary\">{} critical · {} high · {} medium · {} low · {} info</p>\n",
            self.summary.critical,
            self.summary.high,
            self.summary.medium,
            self.summary.low,
            self.summary.info
        ));
        if self.findings.is_empty() {
            out.push_str("<p class=\"clean\">✓ no findings</p>\n</section>\n");
            return out;
        }
        out.push_str("<table>\n<thead><tr><th>Severity</th><th>Finding</th><th>Rule</th>\
                      <th>Location</th><th>Conf.</th><th>Evidence</th></tr></thead>\n<tbody>\n");
        for f in &self.findings {
            out.push_str(&format!(
                "<tr class=\"sev-{sev}\"><td><span class=\"pill pill-{sev}\">{sevu}</span></td>\
                 <td><strong>{title}</strong><br><span class=\"detail\">{detail}</span></td>\
                 <td><code>{rule}</code><br><span class=\"scanner\">{scanner}</span></td>\
                 <td><code>{loc}</code></td><td>{conf:.0}%</td><td>{ev}</td></tr>\n",
                sev = f.severity.as_str(),
                sevu = f.severity.as_str().to_uppercase(),
                title = esc(&f.title),
                detail = esc(&f.detail),
                rule = esc(&f.rule_id),
                scanner = esc(&f.scanner),
                loc = esc(&f.location.component),
                conf = f.confidence * 100.0,
                ev = f.evidence.as_deref().map(esc).unwrap_or_default(),
            ));
        }
        out.push_str("</tbody>\n</table>\n</section>\n");
        out
    }

    /// A complete, self-contained HTML document for a single report.
    pub fn to_html(&self) -> String {
        render_html_document(std::slice::from_ref(self))
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
                out.push_str(&format!(
                    "           {}evidence: {}{}\n",
                    c.dim, ev, c.reset
                ));
            }
        }

        out.push_str(&format!(
            "\n  {}{} critical  {}{} high  {}{} medium  {}{} low  {}{} info{}\n",
            c.red,
            self.summary.critical,
            c.magenta,
            self.summary.high,
            c.yellow,
            self.summary.medium,
            c.blue,
            self.summary.low,
            c.dim,
            self.summary.info,
            c.reset
        ));
        out
    }
}

/// Render one SARIF 2.1.0 document covering many reports as separate results,
/// with each artifact distinguished by its `artifactLocation`. Suitable for a
/// directory scan uploaded to GitHub code scanning as a single run.
pub fn merged_sarif(reports: &[Report]) -> String {
    let mut results = Vec::new();
    for r in reports {
        for f in &r.findings {
            results.push(serde_json::json!({
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
                        "artifactLocation": { "uri": r.target },
                        "logicalLocations": [{ "name": f.location.component }],
                    }
                }],
            }));
        }
    }
    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "TensorHawk",
                "informationUri": "https://github.com/0xsh4n/TensorHawk",
                "version": VERSION,
                "rules": [],
            }},
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default()
}

/// Render a complete HTML document for one or more reports.
pub fn render_html_document(reports: &[Report]) -> String {
    let mut sections = String::new();
    for r in reports {
        sections.push_str(&r.to_html_section());
    }
    let total: usize = reports.iter().map(|r| r.findings.len()).sum();
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>TensorHawk report</title>\n<style>{CSS}</style>\n</head>\n<body>\n\
         <header><h1>🦅 TensorHawk</h1>\
         <p>v{VERSION} · {n} artifact(s) · {total} finding(s)</p></header>\n\
         {sections}\n<footer>Generated by TensorHawk v{VERSION} — static, offline analysis.</footer>\n\
         </body>\n</html>\n",
        n = reports.len(),
    )
}

const CSS: &str = "\
:root{color-scheme:light dark;--bg:#0f1115;--fg:#e6e6e6;--muted:#9aa0a6;--card:#171a21;--border:#2a2f3a;}\
@media(prefers-color-scheme:light){:root{--bg:#f7f7f8;--fg:#1a1a1a;--muted:#666;--card:#fff;--border:#e2e2e2;}}\
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg);padding:0 0 3rem}\
header{padding:1.5rem 2rem;border-bottom:1px solid var(--border)}header h1{margin:0 0 .25rem}header p{margin:0;color:var(--muted)}\
section.report{margin:1.5rem 2rem;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem}\
h2{margin:.2rem 0;font-size:1.1rem;word-break:break-all}.meta,.summary{color:var(--muted);margin:.25rem 0}\
.score{font-weight:700}.score-low{color:#3fb950}.score-med{color:#d29922}.score-high{color:#f85149}\
.clean{color:#3fb950;font-weight:600}\
table{width:100%;border-collapse:collapse;margin-top:.75rem;font-size:.92rem}\
th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--border);vertical-align:top}\
th{color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em}\
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}\
.detail{color:var(--muted);font-size:.88rem}.scanner{color:var(--muted);font-size:.8rem}\
.pill{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.72rem;font-weight:700;color:#fff}\
.pill-critical{background:#f85149}.pill-high{background:#db61a2}.pill-medium{background:#d29922}\
.pill-low{background:#388bfd}.pill-info{background:#6e7681}\
footer{margin:2rem;color:var(--muted);font-size:.85rem}\
";

fn score_class(score: u32) -> &'static str {
    match score {
        0..=19 => "low",
        20..=59 => "med",
        _ => "high",
    }
}

/// Minimal HTML escaping for text interpolated into the report.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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
