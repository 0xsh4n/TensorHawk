//! PII detection over container metadata.
//!
//! Scoped deliberately to the metadata/config surface (author fields, embedded
//! notes, tokenizer config) rather than raw weights, to keep false positives
//! low. Detecting PII that leaked into a shipped artifact is a privacy and
//! compliance concern (GDPR/DPDP), not an accusation about model behavior.

use crate::artifact::Artifact;
use crate::finding::{redact, Finding, Location, Severity};
use crate::scanners::Scanner;
use regex::Regex;

struct Pat {
    rule_id: &'static str,
    name: &'static str,
    severity: Severity,
    re: Regex,
    confidence: f32,
}

pub struct PiiScanner {
    pats: Vec<Pat>,
}

impl PiiScanner {
    pub fn new() -> Self {
        let defs: &[(&str, &str, Severity, &str, f32)] = &[
            (
                "THK-PII-001",
                "Email address",
                Severity::Low,
                r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
                0.7,
            ),
            (
                "THK-PII-002",
                "Credit card number (Luhn-shaped)",
                Severity::High,
                r"\b(?:\d[ \-]?){13,16}\b",
                0.4,
            ),
            (
                "THK-PII-003",
                "US SSN",
                Severity::High,
                r"\b\d{3}-\d{2}-\d{4}\b",
                0.6,
            ),
            (
                "THK-PII-004",
                "India Aadhaar (12-digit)",
                Severity::High,
                r"\b\d{4}\s?\d{4}\s?\d{4}\b",
                0.4,
            ),
            (
                "THK-PII-005",
                "India PAN",
                Severity::Medium,
                r"\b[A-Z]{5}\d{4}[A-Z]\b",
                0.7,
            ),
            (
                "THK-PII-006",
                "IBAN",
                Severity::Medium,
                r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",
                0.6,
            ),
            (
                "THK-PII-007",
                "IPv4 address",
                Severity::Info,
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                0.5,
            ),
        ];
        let pats = defs
            .iter()
            .map(|(rule_id, name, sev, pat, conf)| Pat {
                rule_id,
                name,
                severity: *sev,
                re: Regex::new(pat).expect("valid built-in PII pattern"),
                confidence: *conf,
            })
            .collect();
        PiiScanner { pats }
    }
}

impl Default for PiiScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Luhn checksum, used to suppress false positives on the credit-card pattern.
fn luhn_ok(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 {
        return false;
    }
    let mut sum = 0u32;
    let mut alt = false;
    for &d in digits.iter().rev() {
        let mut d = d;
        if alt {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alt = !alt;
    }
    sum % 10 == 0
}

impl Scanner for PiiScanner {
    fn id(&self) -> &'static str {
        "pii"
    }
    fn description(&self) -> &'static str {
        "Detects personal data leaked into artifact metadata"
    }
    fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (key, value) in &artifact.metadata {
            for p in &self.pats {
                for m in p.re.find_iter(value).take(10) {
                    let hit = m.as_str();
                    // Extra validation for high-FP patterns.
                    if p.rule_id == "THK-PII-002" && !luhn_ok(hit) {
                        continue;
                    }
                    findings.push(
                        Finding::builder(p.rule_id, "pii", p.severity)
                            .title(format!("{} in metadata field `{key}`", p.name))
                            .detail(format!(
                                "A value matching the {} pattern is embedded in artifact \
                                 metadata. If this is real personal data it should not ship \
                                 inside a distributable model file.",
                                p.name
                            ))
                            .location(Location::new(format!("metadata:{key}")))
                            .confidence(p.confidence)
                            .reference("OWASP-LLM06: Sensitive Information Disclosure")
                            .reference("CWE-359: Exposure of Private Personal Information")
                            .evidence(redact(hit))
                            .build(),
                    );
                }
            }
        }
        findings
    }
}
