//! Secret detection.
//!
//! Credentials leak into model artifacts mainly through metadata, tokenizer
//! config, and embedded training/config text — not the float weights. We run a
//! curated set of high-precision patterns over the container metadata and over
//! the raw bytes (via `regex::bytes`, zero-copy on the mmap). Every hit is
//! redacted before it ever reaches a report.

use crate::artifact::Artifact;
use crate::finding::{redact, Finding, Location, Severity};
use crate::scanners::Scanner;
use regex::bytes::Regex;

struct Pattern {
    rule_id: &'static str,
    name: &'static str,
    severity: Severity,
    re: Regex,
    confidence: f32,
}

pub struct SecretScanner {
    patterns: Vec<Pattern>,
}

impl SecretScanner {
    pub fn new() -> Self {
        let defs: &[(&str, &str, Severity, &str, f32)] = &[
            ("THK-SEC-001", "AWS Access Key ID", Severity::Critical,
             r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b", 0.95),
            ("THK-SEC-002", "GitHub Token", Severity::Critical,
             r"\bgh[pousr]_[0-9A-Za-z]{36,}\b", 0.97),
            ("THK-SEC-003", "Slack Token", Severity::High,
             r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", 0.9),
            ("THK-SEC-004", "Google API Key", Severity::High,
             r"\bAIza[0-9A-Za-z_\-]{35}\b", 0.9),
            ("THK-SEC-005", "Stripe Secret Key", Severity::Critical,
             r"\bsk_live_[0-9A-Za-z]{24,}\b", 0.97),
            ("THK-SEC-006", "OpenAI API Key", Severity::Critical,
             r"\bsk-(?:proj-)?[0-9A-Za-z_\-]{20,}\b", 0.8),
            ("THK-SEC-007", "Anthropic API Key", Severity::Critical,
             r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b", 0.95),
            ("THK-SEC-008", "Private Key Block", Severity::Critical,
             r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", 0.98),
            ("THK-SEC-009", "JWT", Severity::Medium,
             r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", 0.75),
            ("THK-SEC-010", "Generic Bearer/Authorization header", Severity::Medium,
             r"(?i)authorization:\s*bearer\s+[0-9A-Za-z._\-]{16,}", 0.6),
            ("THK-SEC-011", "Database connection string", Severity::High,
             r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s:@/]+@", 0.85),
            ("THK-SEC-012", "Google OAuth client secret", Severity::High,
             r"\bGOCSPX-[0-9A-Za-z_\-]{20,}\b", 0.9),
            ("THK-SEC-013", "Twilio Account SID", Severity::Medium,
             r"\bAC[0-9a-fA-F]{32}\b", 0.7),
        ];
        let patterns = defs
            .iter()
            .map(|(rule_id, name, sev, pat, conf)| Pattern {
                rule_id,
                name,
                severity: *sev,
                re: Regex::new(pat).expect("valid built-in secret pattern"),
                confidence: *conf,
            })
            .collect();
        SecretScanner { patterns }
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for SecretScanner {
    fn id(&self) -> &'static str {
        "secrets"
    }
    fn description(&self) -> &'static str {
        "Detects embedded API keys, tokens, and private keys"
    }
    fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1) Metadata strings — highest signal, cheap.
        for (key, value) in &artifact.metadata {
            for p in &self.patterns {
                if let Some(m) = p.re.find(value.as_bytes()) {
                    let hit = String::from_utf8_lossy(m.as_bytes());
                    findings.push(secret_finding(p, &format!("metadata:{key}"), None, &hit));
                }
            }
        }

        // 2) Raw bytes — catches secrets in tokenizer blobs, pickles, headers.
        //    Bounded so we never build huge intermediate buffers.
        let data = artifact.data();
        let scan_len = data.len().min(256 * 1024 * 1024); // cap at 256 MiB for MVP
        let hay = &data[..scan_len];
        for p in &self.patterns {
            for m in p.re.find_iter(hay).take(50) {
                let hit = String::from_utf8_lossy(m.as_bytes());
                findings.push(secret_finding(p, "raw", Some(m.start() as u64), &hit));
            }
        }

        dedup(findings)
    }
}

fn secret_finding(p: &Pattern, component: &str, offset: Option<u64>, hit: &str) -> Finding {
    let loc = match offset {
        Some(o) => Location::at(component, o),
        None => Location::new(component),
    };
    Finding::builder(p.rule_id, "secrets", p.severity)
        .title(format!("{} found in artifact", p.name))
        .detail(format!(
            "A value matching the {} pattern was embedded in the model artifact. \
             Anyone who obtains the model file also obtains this credential.",
            p.name
        ))
        .location(loc)
        .confidence(p.confidence)
        .reference("OWASP-LLM06: Sensitive Information Disclosure")
        .reference("CWE-798: Use of Hard-coded Credentials")
        .remediation("Rotate the exposed credential immediately and rebuild the artifact without it.")
        .evidence(redact(hit))
        .build()
}

/// Collapse duplicate (rule_id, evidence) findings that appear in both the
/// metadata and raw passes.
fn dedup(mut findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let key = (f.rule_id.clone(), f.evidence.clone());
        seen.insert(key)
    });
    findings
}
