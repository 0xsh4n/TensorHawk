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

    /// A detailed, self-contained HTML fragment (the `<section>` for this
    /// artifact): an artifact header with risk/format/size, a severity summary,
    /// then one card per finding. Each finding leads with its public framework
    /// classification (MITRE ATLAS / OWASP LLM / CWE) rather than the internal
    /// detection code, and carries full detail, evidence, and remediation.
    fn to_html_section(&self, index: usize) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "<section class=\"report\">\n\
             <div class=\"report-head\">\n\
             <h3 class=\"art-name\"><span class=\"art-n\">Artifact {idx}</span>{target}</h3>\n\
             <div class=\"badges\"><span class=\"score score-{sc}\">Risk {score}/100</span>\
             <span class=\"badge\">{fmt}</span><span class=\"badge\">{size}</span></div>\n</div>\n",
            idx = index,
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
            out.push_str("<p class=\"clean\">No findings.</p>\n</section>\n");
            return out;
        }
        for f in &self.findings {
            let sev = f.severity.as_str();
            out.push_str(&format!(
                "<article class=\"finding sev-{sev}\">\n\
                 <div class=\"f-head\"><span class=\"pill pill-{sev}\">{sevu}</span>\
                 <h4>{title}</h4><span class=\"conf\">Confidence {conf:.0}%</span></div>\n",
                sevu = sev.to_uppercase(),
                title = esc(&f.title),
                conf = f.confidence * 100.0,
            ));
            // Public framework classification leads the finding.
            let chips = framework_chips(&f.references);
            if !chips.is_empty() {
                out.push_str(&format!("<div class=\"f-cls\">{chips}</div>\n"));
            }
            out.push_str(&format!(
                "<p class=\"f-detail\">{detail}</p>\n\
                 <dl class=\"f-meta\">\
                 <div><dt>Scanner</dt><dd>{scanner}</dd></div>\
                 <div><dt>Location</dt><dd><code>{loc}</code></dd></div>\
                 <div><dt>Detection ID</dt><dd><code>{rule}</code></dd></div></dl>\n",
                detail = esc(&f.detail),
                scanner = esc(&f.scanner),
                loc = esc(&location_str(&f.location)),
                rule = esc(&f.rule_id),
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
            results.push(sarif_result(f, &r.target));
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

/// Build the SARIF `result` object for a single finding at `uri`.
fn sarif_result(f: &Finding, uri: &str) -> serde_json::Value {
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
                "artifactLocation": { "uri": uri },
                "logicalLocations": [{ "name": f.location.component }],
            }
        }],
    })
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
    for (i, r) in reports.iter().enumerate() {
        sections.push_str(&r.to_html_section(i + 1));
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
    let prepared_by = author.unwrap_or("TensorHawk");
    let generated = opts.generated_at.as_deref().unwrap_or("—");

    // Overall posture, derived from the worst severity present.
    let (p_label, p_text, p_class) = if agg.critical > 0 {
        ("Critical", "Critical issues were identified. Immediate remediation is required before these artifacts are trusted or deployed.", "critical")
    } else if agg.high > 0 {
        (
            "High",
            "High-severity issues were identified. Remediation is required before use.",
            "high",
        )
    } else if agg.medium > 0 {
        (
            "Elevated",
            "Moderate issues were identified. Remediation is recommended prior to use.",
            "medium",
        )
    } else if agg.low > 0 {
        (
            "Low",
            "Only low-severity issues were identified. Review at your discretion.",
            "low",
        )
    } else if total > 0 {
        ("Informational", "No security-relevant issues were identified; only informational observations are reported.", "info")
    } else {
        (
            "Clean",
            "No findings were produced for the assessed artifacts.",
            "info",
        )
    };

    let overall = format!(
        "{}{}{}{}{}",
        sev_chip("critical", agg.critical),
        sev_chip("high", agg.high),
        sev_chip("medium", agg.medium),
        sev_chip("low", agg.low),
        sev_chip("info", agg.info),
    );

    let author_row = author
        .map(|a| format!("<tr><th>Prepared&nbsp;by</th><td>{}</td></tr>", esc(a)))
        .unwrap_or_default();
    let footer_left = format!("Prepared by {}", esc(prepared_by));

    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>TensorHawk — Security Assessment Report</title>\n<style>{css}</style>\n</head>\n<body>\n\
         <header class=\"doc-head\">\n\
         <div class=\"brand\"><span class=\"mark\">TH</span>\
         <div class=\"brand-text\"><div class=\"brand-name\">TensorHawk</div>\
         <div class=\"brand-tag\">Security Assessment Report</div></div></div>\n\
         <table class=\"doc-info\"><tbody>{author_row}\
         <tr><th>Date</th><td>{generated}</td></tr>\
         <tr><th>Tool</th><td>TensorHawk v{VERSION}</td></tr>\
         <tr><th>Scope</th><td>{n} artifact(s)</td></tr></tbody></table>\n</header>\n\
         <main>\n\
         <section class=\"exec\">\n<h2>Executive Summary</h2>\n\
         <div class=\"posture posture-{p_class}\"><span class=\"posture-label\">{p_label} risk</span>\
         <p>{p_text}</p></div>\n\
         <p class=\"exec-line\">{n} artifact(s) were assessed and {total} finding(s) were recorded, \
         distributed as follows:</p>\n<div class=\"summary\">{overall}</div>\n\
         <h3>Methodology</h3>\n\
         <p class=\"method\">TensorHawk performs static, offline inspection of model and dataset \
         artifacts. No model code is executed and no network connection is made. Each finding \
         carries a confidence value and is mapped, where applicable, to public security \
         frameworks — the OWASP Top&nbsp;10 for LLM Applications, MITRE ATLAS, and CWE. Heuristic \
         and experimental signals are indicators for investigation and are not, by themselves, \
         proof of compromise.</p>\n</section>\n\
         <section class=\"findings-wrap\"><h2>Detailed Findings</h2>\n{sections}</section>\n\
         </main>\n\
         <footer class=\"doc-foot\"><span>{footer_left}</span>\
         <span>TensorHawk v{VERSION} · {generated} · static offline analysis</span></footer>\n\
         </body>\n</html>\n",
        css = css(author.unwrap_or("")),
    )
}

/// Build the stylesheet, injecting the author into the `@page` running footer.
fn css(author: &str) -> String {
    let page_author = if author.is_empty() {
        String::new()
    } else {
        format!(
            "@bottom-left{{content:\"Prepared by {}\";font-size:8pt;color:#6a7686}}",
            css_escape(author)
        )
    };
    format!(
        "@page{{size:A4;margin:18mm 15mm 18mm 15mm;\
         @top-left{{content:\"TensorHawk — Security Assessment Report\";font-size:8pt;color:#6a7686}}\
         @top-right{{content:\"v{VERSION}\";font-size:8pt;color:#6a7686}}\
         {page_author}\
         @bottom-right{{content:\"Page \" counter(page) \" of \" counter(pages);font-size:8pt;color:#6a7686}}}}\
         {BASE_CSS}"
    )
}

/// Escape a string for safe use inside a CSS `content:\"...\"` literal.
fn css_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// Professional, bicolor (navy / light-blue on white) report stylesheet.
const BASE_CSS: &str = "\
:root{--navy:#123a63;--blue:#1f6fb2;--sky:#eaf2fb;--sky-line:#cfe0f2;--ink:#1e2a38;--muted:#5a6a7a;--line:#dde6ef;--bg:#ffffff;\
--crit:#b22216;--high:#c06a0e;--med:#a9810c;--low:#1f6fb2;--info:#6b7684;}\
*{box-sizing:border-box}\
body{margin:0;font:13.5px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink);padding:0 0 2rem}\
.doc-head{display:flex;justify-content:space-between;align-items:center;gap:1.5rem;flex-wrap:wrap;padding:1.4rem 2.2rem;background:var(--sky);border-bottom:3px solid var(--navy)}\
.brand{display:flex;align-items:center;gap:.85rem}\
.mark{display:inline-flex;align-items:center;justify-content:center;width:42px;height:42px;border-radius:9px;background:var(--navy);color:#fff;font-weight:800;font-size:1.05rem;letter-spacing:.04em}\
.brand-name{font-size:1.5rem;font-weight:800;color:var(--navy);letter-spacing:.01em;line-height:1.1}\
.brand-tag{font-size:.72rem;color:var(--blue);text-transform:uppercase;letter-spacing:.14em;font-weight:600}\
.doc-info{border-collapse:collapse;font-size:.78rem}\
.doc-info th{text-align:right;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em;padding:.1rem .7rem .1rem 0;font-size:.68rem;white-space:nowrap}\
.doc-info td{text-align:left;color:var(--ink);padding:.1rem 0;font-weight:600}\
main{padding:0 2.2rem}\
h2{color:var(--navy);font-size:1.15rem;margin:1.6rem 0 .6rem;padding-bottom:.35rem;border-bottom:2px solid var(--sky-line)}\
h3{color:var(--navy);font-size:.95rem;margin:1rem 0 .4rem}\
.exec .exec-line{margin:.6rem 0 .3rem;color:var(--muted)}\
.posture{display:flex;align-items:baseline;gap:.8rem;flex-wrap:wrap;background:var(--sky);border:1px solid var(--sky-line);border-left:4px solid var(--navy);border-radius:7px;padding:.7rem .9rem;margin:.4rem 0}\
.posture p{margin:0;color:var(--ink)}\
.posture-label{font-weight:800;color:#fff;background:var(--navy);border-radius:5px;padding:.15rem .6rem;font-size:.78rem;white-space:nowrap}\
.posture-critical .posture-label{background:var(--crit)}.posture-high .posture-label{background:var(--high)}\
.posture-medium .posture-label{background:var(--med)}.posture-low .posture-label{background:var(--low)}\
.posture-info .posture-label{background:var(--info)}\
.method{color:var(--muted);font-size:.86rem;max-width:62rem}\
.summary{margin:.5rem 0;display:flex;gap:.45rem;flex-wrap:wrap}\
.chip{display:inline-block;padding:.14rem .6rem;border-radius:5px;font-size:.72rem;font-weight:700;border:1px solid var(--line);background:#f6f9fc;color:var(--ink)}\
.chip-0{opacity:.45}\
.chip.critical{border-left:3px solid var(--crit)}.chip.high{border-left:3px solid var(--high)}\
.chip.medium{border-left:3px solid var(--med)}.chip.low{border-left:3px solid var(--low)}\
.chip.info{border-left:3px solid var(--info)}\
section.report{margin:1rem 0;background:var(--bg);border:1px solid var(--line);border-radius:9px;padding:.9rem 1.1rem}\
.report-head{break-after:avoid}\
h2{break-after:avoid}\
.report-head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:.55rem;margin-bottom:.3rem}\
.art-name{margin:0;font-size:1rem;color:var(--navy);word-break:break-all}\
.art-n{display:inline-block;font-size:.66rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--blue);background:var(--sky);border:1px solid var(--sky-line);border-radius:4px;padding:.05rem .4rem;margin-right:.5rem;vertical-align:middle}\
.badges{display:flex;gap:.4rem;flex-wrap:wrap;align-items:center}\
.badge{font-size:.72rem;color:var(--muted);border:1px solid var(--line);border-radius:5px;padding:.1rem .45rem;background:#f6f9fc}\
.score{font-weight:800;font-size:.74rem;border-radius:5px;padding:.14rem .5rem;color:#fff}\
.score-low{background:#2f8f4e}.score-med{background:var(--med)}.score-high{background:var(--crit)}\
.clean{color:#2f8f4e;font-weight:700;margin:.4rem 0}\
.finding{border:1px solid var(--line);border-left:4px solid var(--info);border-radius:7px;padding:.65rem .85rem;margin:.7rem 0;break-inside:avoid}\
.finding.sev-critical{border-left-color:var(--crit)}.finding.sev-high{border-left-color:var(--high)}\
.finding.sev-medium{border-left-color:var(--med)}.finding.sev-low{border-left-color:var(--low)}\
.finding.sev-info{border-left-color:var(--info)}\
.f-head{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap}\
.f-head h4{margin:0;font-size:.95rem;color:var(--ink);flex:1 1 auto}.conf{color:var(--muted);font-size:.76rem}\
.pill{display:inline-block;padding:.1rem .5rem;border-radius:4px;font-size:.66rem;font-weight:800;color:#fff;letter-spacing:.05em}\
.pill-critical{background:var(--crit)}.pill-high{background:var(--high)}.pill-medium{background:var(--med)}\
.pill-low{background:var(--low)}.pill-info{background:var(--info)}\
.f-cls{display:flex;gap:.4rem;flex-wrap:wrap;margin:.45rem 0}\
.cls{font-size:.7rem;font-weight:700;border-radius:4px;padding:.1rem .5rem;border:1px solid var(--sky-line);background:var(--sky);color:var(--navy)}\
.cls.atlas{background:#eef4fb;border-color:#c8ddf2;color:#0f4c81}\
.cls.owasp{background:#eaf3ee;border-color:#c6e0d0;color:#1d6b43}\
.cls.cwe{background:#f1f0fb;border-color:#d4d0ee;color:#4a3f8f}\
.cls.cve{background:#fbf0ee;border-color:#eecfc8;color:#8f3a2e}\
.f-detail{margin:.4rem 0;color:var(--ink)}\
.f-meta{display:flex;flex-wrap:wrap;gap:.25rem 1.6rem;margin:.45rem 0;padding:0}\
.f-meta>div{display:flex;gap:.4rem;align-items:baseline}\
.f-meta dt{margin:0;color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.04em;white-space:nowrap}\
.f-meta dd{margin:0;font-size:.82rem}\
.f-row{margin:.4rem 0;font-size:.84rem}\
.lbl{display:inline-block;min-width:6rem;color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.04em;vertical-align:top}\
.f-ev code{background:#f3f6f9;border:1px solid var(--line);padding:.1rem .35rem;border-radius:4px}\
.f-rem{background:var(--sky);border:1px solid var(--sky-line);border-radius:6px;padding:.4rem .6rem}\
.f-ref ul{display:inline-block;margin:0;padding-left:1.1rem;vertical-align:top}.f-ref li{font-size:.8rem;color:var(--muted)}\
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em}\
.doc-foot{display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin:2rem 2.2rem 0;padding-top:.8rem;border-top:2px solid var(--sky-line);color:var(--muted);font-size:.76rem}\
";

/// Render the public-framework classification chips for a finding, derived from
/// its references (MITRE ATLAS / OWASP LLM / CWE / CVE). Internal `THK-` codes
/// are never shown here — the public mapping leads.
fn framework_chips(references: &[String]) -> String {
    let mut seen: Vec<String> = Vec::new();
    let mut out = String::new();
    for r in references {
        if let Some((class, label)) = framework_tag(r) {
            if seen.iter().any(|s| s == &label) {
                continue;
            }
            seen.push(label.clone());
            out.push_str(&format!(
                "<span class=\"cls {class}\">{}</span>",
                esc(&label)
            ));
        }
    }
    out
}

/// Classify a reference string into `(css_class, short_public_id)` for the
/// recognized public frameworks, or `None` for anything else.
fn framework_tag(r: &str) -> Option<(&'static str, String)> {
    let head = r.split(':').next().unwrap_or("").trim();
    let upper = head.to_ascii_uppercase();
    if upper.contains("ATLAS") {
        let tok = r.split_whitespace().find(|w| w.starts_with("AML."));
        let label = match tok {
            Some(t) => format!("MITRE ATLAS {t}"),
            None => "MITRE ATLAS".to_string(),
        };
        return Some(("atlas", label));
    }
    if upper.starts_with("OWASP") {
        // "OWASP-LLM05" -> "OWASP LLM05"
        return Some((
            "owasp",
            head.replacen("OWASP-", "OWASP ", 1).replace('-', " "),
        ));
    }
    if upper.starts_with("CWE-") {
        return Some(("cwe", head.to_string()));
    }
    if upper.starts_with("CVE-") {
        return Some(("cve", head.to_string()));
    }
    None
}

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
