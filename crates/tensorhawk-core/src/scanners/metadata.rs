//! Metadata inspection.
//!
//! Surfaces provenance and infrastructure fingerprints that leak through
//! container metadata: absolute build paths (which expose usernames/hostnames),
//! internal URLs, cloud identifiers, and author/organization strings. These are
//! low severity individually but valuable for supply-chain attribution.

use crate::artifact::Artifact;
use crate::finding::{Finding, Location, Severity};
use crate::scanners::Scanner;
use regex::Regex;

pub struct MetadataScanner {
    url: Regex,
    unix_home: Regex,
    win_path: Regex,
    cloud: Regex,
}

impl MetadataScanner {
    pub fn new() -> Self {
        MetadataScanner {
            url: Regex::new(r#"https?://[^\s"'<>]+"#).unwrap(),
            unix_home: Regex::new(r"/(?:home|Users|root)/[A-Za-z0-9._\-]+").unwrap(),
            win_path: Regex::new(r"[A-Za-z]:\\Users\\[A-Za-z0-9._\-]+").unwrap(),
            cloud: Regex::new(
                r"(?i)\b(?:s3://|gs://|azureml|sagemaker|ec2-\d|\.internal\b|10\.\d+\.\d+\.\d+)",
            )
            .unwrap(),
        }
    }
}

impl Default for MetadataScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner for MetadataScanner {
    fn id(&self) -> &'static str {
        "metadata"
    }
    fn description(&self) -> &'static str {
        "Surfaces provenance and infrastructure fingerprints in metadata"
    }
    fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (key, value) in &artifact.metadata {
            let comp = format!("metadata:{key}");

            if let Some(m) = self
                .unix_home
                .find(value)
                .or_else(|| self.win_path.find(value))
            {
                findings.push(
                    Finding::builder("THK-MET-001", "metadata", Severity::Low)
                        .title("Absolute build path leaks a username/host")
                        .detail(format!(
                            "Metadata field `{key}` contains a filesystem path that reveals \
                             the account or machine used to build the model."
                        ))
                        .location(Location::new(&comp))
                        .confidence(0.85)
                        .reference("OWASP-LLM06: Sensitive Information Disclosure")
                        .evidence(m.as_str().to_string())
                        .build(),
                );
            }
            if let Some(m) = self.cloud.find(value) {
                findings.push(
                    Finding::builder("THK-MET-002", "metadata", Severity::Low)
                        .title("Cloud / internal-network identifier in metadata")
                        .detail(format!(
                            "Metadata field `{key}` references cloud storage or an internal \
                             endpoint, exposing training infrastructure."
                        ))
                        .location(Location::new(&comp))
                        .confidence(0.7)
                        .evidence(m.as_str().to_string())
                        .build(),
                );
            }
            for m in self.url.find_iter(value).take(5) {
                findings.push(
                    Finding::builder("THK-MET-003", "metadata", Severity::Info)
                        .title("Embedded URL in metadata")
                        .detail(format!("Metadata field `{key}` embeds a URL."))
                        .location(Location::new(&comp))
                        .confidence(0.9)
                        .evidence(m.as_str().to_string())
                        .build(),
                );
            }
        }

        // Inventory line so a clean report still shows what was parsed.
        if !artifact.metadata.is_empty() || artifact.tensor_count.is_some() {
            let tc = artifact
                .tensor_count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into());
            findings.push(
                Finding::builder("THK-MET-000", "metadata", Severity::Info)
                    .title("Artifact inventory")
                    .detail(format!(
                        "Parsed {} metadata key(s); container declares {} tensor(s).",
                        artifact.metadata.len(),
                        tc
                    ))
                    .location(Location::new("header"))
                    .confidence(1.0)
                    .build(),
            );
        }
        findings
    }
}
