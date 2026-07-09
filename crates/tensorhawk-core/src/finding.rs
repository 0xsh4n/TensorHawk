//! Findings, severities, and risk taxonomy shared across all scanners.

use serde::{Deserialize, Serialize};

/// Severity of a finding, ordered from least to most serious.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// SARIF only distinguishes error/warning/note.
    pub fn sarif_level(&self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }

    /// Coarse numeric weight used for the aggregate risk score.
    pub fn weight(&self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 4,
            Severity::High => 8,
            Severity::Critical => 16,
        }
    }
}

/// Where inside an artifact a finding was located.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Location {
    /// Logical component, e.g. `metadata`, `archive:data.pkl`, `header`.
    pub component: String,
    /// Byte offset within that component, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

impl Location {
    pub fn new(component: impl Into<String>) -> Self {
        Self {
            component: component.into(),
            offset: None,
        }
    }
    pub fn at(component: impl Into<String>, offset: u64) -> Self {
        Self {
            component: component.into(),
            offset: Some(offset),
        }
    }
}

/// A single security-relevant observation about a model artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier, e.g. `THK-PKL-001`.
    pub rule_id: String,
    /// Scanner that produced this finding, e.g. `pickle`.
    pub scanner: String,
    pub severity: Severity,
    /// 0.0..=1.0 confidence that this is a true positive.
    pub confidence: f32,
    pub title: String,
    pub detail: String,
    pub location: Location,
    /// Risk-framework cross references (OWASP LLM Top 10, MITRE ATLAS, CWE).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub references: Vec<String>,
    /// Suggested remediation, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// A short redacted evidence snippet. Secrets are never emitted in full.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

impl Finding {
    pub fn builder(rule_id: &str, scanner: &str, severity: Severity) -> FindingBuilder {
        FindingBuilder {
            f: Finding {
                rule_id: rule_id.to_string(),
                scanner: scanner.to_string(),
                severity,
                confidence: 0.8,
                title: String::new(),
                detail: String::new(),
                location: Location::default(),
                references: Vec::new(),
                remediation: None,
                evidence: None,
            },
        }
    }
}

pub struct FindingBuilder {
    f: Finding,
}

impl FindingBuilder {
    pub fn title(mut self, v: impl Into<String>) -> Self {
        self.f.title = v.into();
        self
    }
    pub fn detail(mut self, v: impl Into<String>) -> Self {
        self.f.detail = v.into();
        self
    }
    pub fn confidence(mut self, v: f32) -> Self {
        self.f.confidence = v.clamp(0.0, 1.0);
        self
    }
    pub fn location(mut self, v: Location) -> Self {
        self.f.location = v;
        self
    }
    pub fn reference(mut self, v: impl Into<String>) -> Self {
        self.f.references.push(v.into());
        self
    }
    pub fn remediation(mut self, v: impl Into<String>) -> Self {
        self.f.remediation = Some(v.into());
        self
    }
    pub fn evidence(mut self, v: impl Into<String>) -> Self {
        self.f.evidence = Some(v.into());
        self
    }
    pub fn build(self) -> Finding {
        self.f
    }
}

/// Redact a secret-like string, keeping only enough to identify it.
pub fn redact(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        return "*".repeat(n);
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("{head}…{tail} ({n} chars)")
}
