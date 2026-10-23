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

    /// A detailed, self-contained HTML fragment (the `<section>` for this
    /// artifact): a header with risk/format/size, a severity summary, then one
    /// rich card per finding carrying its full detail, evidence, remediation,
    /// and framework references.
    fn to_html_section(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "<section class=\"report\">\n\
             <div class=\"report-head\">\n<h2>{target}</h2>\n\
             <div class=\"badges\"><span class=\"score score-{sc}\">Risk {score}/100</span>\
             <span class=\"badge fmt\">{fmt}</span><span class=\"badge\">{size}</span></div>\n</div>\n",
            target = esc(&self.target),
            sc = score_class(self.risk_score),
            score = self.risk_score,
            fmt = esc(&self.format),
            size = human_bytes(self.bytes),
        ));
        out.push_str(&format!(
            "<p class=\"summary\">{}{}{}{}{}</p>\n",
            sev_chip("critical", self.summary.critical),
            sev_chip("high", self.summary.high),
            sev_chip("medium", self.summary.medium),
            sev_chip("low", self.summary.low),
            sev_chip("info", self.summary.info),
        ));
        if self.findings.is_empty() {
            out.push_str("<p class=\"clean\">✓ No findings</p>\n</section>\n");
            return out;
        }
        for f in &self.findings {
            let sev = f.severity.as_str();
            out.push_str(&format!(
                "<article class=\"finding sev-{sev}\">\n\
                 <div class=\"f-head\"><span class=\"pill pill-{sev}\">{sevu}</span>\
                 <h3>{title}</h3><span class=\"conf\">{conf:.0}% confidence</span></div>\n\
                 <p class=\"f-detail\">{detail}</p>\n\
                 <dl class=\"f-meta\">\
                 <div><dt>Rule</dt><dd><code>{rule}</code></dd></div>\
                 <div><dt>Scanner</dt><dd>{scanner}</dd></div>\
                 <div><dt>Location</dt><dd><code>{loc}</code></dd></div></dl>\n",
                sevu = sev.to_uppercase(),
                title = esc(&f.title),
                conf = f.confidence * 100.0,
                detail = esc(&f.detail),
                rule = esc(&f.rule_id),
                scanner = esc(&f.scanner),
                loc = esc(&location_str(&f.location)),
            ));
            if let Some(ev) = &f.evidence {
                out.push_str(&format!(
                    "<div class=\"f-row f-ev\"><span class=\"lbl\">Evidence</span>\
                     <code>{}</code></div>\n",
                    esc(ev)
                ));
            }
            if let Some(rem) = &f.remediation {
                out.push_str(&format!(
                    "<div class=\"f-row f-rem\"><span class=\"lbl\">Remediation</span>\
                     <span>{}</span></div>\n",
                    esc(rem)
                ));
            }
            if !f.references.is_empty() {
                let items: String = f
                    .references
                    .iter()
                    .map(|r| format!("<li>{}</li>", esc(r)))
                    .collect();
                out.push_str(&format!(
                    "<div class=\"f-row f-ref\"><span class=\"lbl\">References</span>\
                     <ul>{items}</ul></div>\n"
                ));
            }
            out.push_str("</article>\n");
        }
        out.push_str("</section>\n");
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

/// Options controlling the branded HTML/PDF report document.
#[derive(Debug, Clone, Default)]
pub struct HtmlReportOptions {
    /// Author shown in the header and footer (e.g. `0xsh4n`). Empty/None = omit.
    pub author: Option<String>,
    /// Preformatted generation timestamp (e.g. `2026-10-23 14:05 UTC`).
    pub generated_at: Option<String>,
}

/// Render a complete HTML document for one or more reports, with default
/// (unbranded) options. Kept for backward compatibility.
pub fn render_html_document(reports: &[Report]) -> String {
    render_html_report(reports, &HtmlReportOptions::default())
}

/// Render a complete, self-contained, print-ready HTML document for one or more
/// reports, with a branded TensorHawk header/footer and optional author. The
/// document carries `@page` rules so a converter (e.g. WeasyPrint) produces a
/// paginated PDF with running header/footer and page numbers.
pub fn render_html_report(reports: &[Report], opts: &HtmlReportOptions) -> String {
    let mut sections = String::new();
    for r in reports {
        sections.push_str(&r.to_html_section());
    }

    let n = reports.len();
    let total: usize = reports.iter().map(|r| r.findings.len()).sum();
    let mut agg = Summary::default();
    for r in reports {
        agg.critical += r.summary.critical;
        agg.high += r.summary.high;
        agg.medium += r.summary.medium;
        agg.low += r.summary.low;
        agg.info += r.summary.info;
    }

    let author = opts
        .author
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty());
    let generated = opts.generated_at.as_deref().unwrap_or("");

    // Header meta line: author · timestamp · tool version.
    let mut meta_bits: Vec<String> = Vec::new();
    if let Some(a) = author {
        meta_bits.push(format!("Author <strong>{}</strong>", esc(a)));
    }
    if !generated.is_empty() {
        meta_bits.push(format!("Generated {}", esc(generated)));
    }
    meta_bits.push(format!("TensorHawk v{VERSION}"));
    let header_meta = meta_bits.join(" &nbsp;·&nbsp; ");

    // Footer author clause (also used in the @page running footer).
    let footer_author = author
        .map(|a| format!("Author: {} · ", esc(a)))
        .unwrap_or_default();

    // Overall severity summary chips for the cover.
    let overall = format!(
        "{}{}{}{}{}",
        sev_chip("critical", agg.critical),
        sev_chip("high", agg.high),
        sev_chip("medium", agg.medium),
        sev_chip("low", agg.low),
        sev_chip("info", agg.info),
    );

    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>TensorHawk Security Report</title>\n<style>{css}</style>\n</head>\n<body>\n\
         <header class=\"doc-head\">\n\
         <div class=\"brand\"><span class=\"logo\">🦅</span>\
         <div><div class=\"brand-name\">TensorHawk</div>\
         <div class=\"brand-tag\">AI Model &amp; Dataset Security Report</div></div></div>\n\
         <div class=\"doc-meta\">{header_meta}</div>\n</header>\n\
         <section class=\"overview\">\n\
         <p class=\"ov-line\">{n} artifact(s) scanned &nbsp;·&nbsp; {total} finding(s)</p>\n\
         <p class=\"summary\">{overall}</p>\n\
         <p class=\"disclaimer\">Static, offline analysis — no model code was executed and no \
         network was used. Findings carry a confidence; heuristic/experimental signals are \
         indicators to investigate, not proof.</p>\n</section>\n\
         {sections}\n\
         <footer class=\"doc-foot\">{footer_author}TensorHawk v{VERSION} — static offline analysis. \
         {generated}</footer>\n\
         </body>\n</html>\n",
        css = css(author.unwrap_or("")),
    )
}

/// Build the stylesheet, injecting the author into the `@page` running footer.
fn css(author: &str) -> String {
    let page_author = if author.is_empty() {
        String::new()
    } else {
        // `string-set` would be cleaner but is less universally supported; inline
        // the author directly into the bottom-left margin box.
        format!(
            "@bottom-left{{content:\"Author: {}\";font-size:8pt;color:#888}}",
            css_escape(author)
        )
    };
    format!(
        "@page{{size:A4;margin:16mm 14mm 18mm 14mm;\
         @top-left{{content:\"TensorHawk — AI Model & Dataset Security Report\";font-size:8pt;color:#888}}\
         @top-right{{content:\"v{VERSION}\";font-size:8pt;color:#888}}\
         {page_author}\
         @bottom-right{{content:\"Page \" counter(page) \" of \" counter(pages);font-size:8pt;color:#888}}}}\
         {BASE_CSS}"
    )
}

/// Escape a string for safe use inside a CSS `content:\"...\"` literal.
fn css_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

const BASE_CSS: &str = "\
:root{color-scheme:light dark;--bg:#ffffff;--fg:#1a1d23;--muted:#5c6370;--card:#ffffff;--border:#e3e6ea;--accent:#b3132a;--head:#14171c;}\
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e6e6e6;--muted:#9aa0a6;--card:#171a21;--border:#2a2f3a;--accent:#ff5d6c;--head:#0b0d11;}}\
*{box-sizing:border-box}\
body{margin:0;font:14px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg);padding:0 0 3rem}\
.doc-head{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;padding:1.25rem 2rem;background:var(--head);color:#fff;border-bottom:3px solid var(--accent)}\
.brand{display:flex;align-items:center;gap:.7rem}.logo{font-size:2rem;line-height:1}\
.brand-name{font-size:1.4rem;font-weight:800;letter-spacing:.02em}\
.brand-tag{font-size:.8rem;color:#b9bfc8}\
.doc-meta{font-size:.82rem;color:#c3c9d2;text-align:right}.doc-meta strong{color:#fff}\
.overview{margin:1.5rem 2rem 0}.ov-line{font-weight:600;margin:.25rem 0}\
.disclaimer{color:var(--muted);font-size:.82rem;margin:.5rem 0 0;max-width:60rem}\
.summary{margin:.5rem 0;display:flex;gap:.4rem;flex-wrap:wrap}\
.chip{display:inline-block;padding:.12rem .55rem;border-radius:999px;font-size:.74rem;font-weight:700;border:1px solid var(--border)}\
.chip-0{opacity:.5}\
.chip.critical{background:#fde7ea;color:#9b1020;border-color:#f2b8c0}\
.chip.high{background:#fde9f1;color:#9b1368;border-color:#f3bcd7}\
.chip.medium{background:#fdf3e0;color:#8a5a00;border-color:#f1d9a8}\
.chip.low{background:#e7f0fd;color:#13508a;border-color:#bcd4f3}\
.chip.info{background:#eef0f2;color:#4a5160;border-color:#d7dbe0}\
section.report{margin:1.25rem 2rem;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;break-inside:avoid}\
.report-head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap;border-bottom:1px solid var(--border);padding-bottom:.5rem}\
h2{margin:.1rem 0;font-size:1.05rem;word-break:break-all}\
.badges{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center}\
.badge{font-size:.74rem;color:var(--muted);border:1px solid var(--border);border-radius:6px;padding:.1rem .45rem}\
.score{font-weight:800;font-size:.78rem;border-radius:6px;padding:.12rem .5rem;color:#fff}\
.score-low{background:#2f9e44}.score-med{background:#d29922}.score-high{background:#c92a2a}\
.clean{color:#2f9e44;font-weight:700}\
.finding{border:1px solid var(--border);border-left:4px solid var(--border);border-radius:8px;padding:.6rem .8rem;margin:.7rem 0;break-inside:avoid}\
.finding.sev-critical{border-left-color:#c92a2a}.finding.sev-high{border-left-color:#d6336c}\
.finding.sev-medium{border-left-color:#d29922}.finding.sev-low{border-left-color:#1c7ed6}\
.finding.sev-info{border-left-color:#868e96}\
.f-head{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}\
.f-head h3{margin:0;font-size:.98rem;flex:1 1 auto}.conf{color:var(--muted);font-size:.78rem}\
.pill{display:inline-block;padding:.08rem .5rem;border-radius:999px;font-size:.68rem;font-weight:800;color:#fff;letter-spacing:.03em}\
.pill-critical{background:#c92a2a}.pill-high{background:#d6336c}.pill-medium{background:#d29922}\
.pill-low{background:#1c7ed6}.pill-info{background:#868e96}\
.f-detail{margin:.4rem 0;color:var(--fg)}\
.f-meta{display:flex;flex-wrap:wrap;gap:.3rem 1.4rem;margin:.4rem 0;padding:0}\
.f-meta>div{display:flex;gap:.35rem;align-items:baseline}\
.f-meta dt{margin:0;color:var(--muted);font-size:.74rem;text-transform:uppercase;letter-spacing:.03em}\
.f-meta dd{margin:0;font-size:.82rem}\
.f-row{margin:.35rem 0;font-size:.84rem}\
.lbl{display:inline-block;min-width:5.5rem;color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.03em;vertical-align:top}\
.f-ev code{background:rgba(127,127,127,.12);padding:.08rem .3rem;border-radius:4px}\
.f-rem{background:rgba(47,158,68,.08);border:1px solid rgba(47,158,68,.25);border-radius:6px;padding:.35rem .5rem}\
.f-ref ul{display:inline-block;margin:0;padding-left:1.1rem}.f-ref li{font-size:.8rem;color:var(--muted)}\
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85em}\
.doc-foot{margin:2rem;padding-top:1rem;border-top:1px solid var(--border);color:var(--muted);font-size:.8rem}\
";

fn score_class(score: u32) -> &'static str {
    match score {
        0..=19 => "low",
        20..=59 => "med",
        _ => "high",
    }
}

/// A severity count chip for the summary rows; dimmed when the count is zero.
fn sev_chip(kind: &str, n: usize) -> String {
    let dim = if n == 0 { " chip-0" } else { "" };
    format!("<span class=\"chip {kind}{dim}\">{n} {kind}</span>")
}

/// Render a finding location as `component` or `component @offset`.
fn location_str(loc: &crate::finding::Location) -> String {
    match loc.offset {
        Some(o) => format!("{} @{o}", loc.component),
        None => loc.component.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Location};

    fn sample_report() -> Report {
        let f = Finding::builder("THK-TST-001", "test", Severity::High)
            .title("Example finding")
            .detail("A detailed description.")
            .location(Location::at("component", 42))
            .remediation("Do the safe thing instead.")
            .reference("CWE-000: Example")
            .evidence("ab…yz (8 chars)")
            .build();
        Report::new("model.bin".into(), "gguf".into(), 1024, vec![f])
    }

    #[test]
    fn branded_report_includes_author_and_full_detail() {
        let opts = HtmlReportOptions {
            author: Some("0xsh4n".into()),
            generated_at: Some("2026-10-23 12:00 UTC".into()),
        };
        let html = render_html_report(std::slice::from_ref(&sample_report()), &opts);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("TensorHawk"));
        assert!(html.contains("0xsh4n")); // header byline + @page footer
        assert!(html.contains("2026-10-23 12:00 UTC"));
        // Detailed fields that the old table dropped are now present.
        assert!(html.contains("Do the safe thing instead.")); // remediation
        assert!(html.contains("CWE-000: Example")); // reference
        assert!(html.contains("component @42")); // location with offset
                                                 // Self-contained: no external resource loads.
        assert!(!html.contains("http://"));
        assert!(!html.contains("src=\"http"));
    }

    #[test]
    fn empty_author_omits_byline() {
        let opts = HtmlReportOptions {
            author: Some("   ".into()),
            generated_at: None,
        };
        let html = render_html_report(std::slice::from_ref(&sample_report()), &opts);
        assert!(!html.contains("Author"));
    }
}
