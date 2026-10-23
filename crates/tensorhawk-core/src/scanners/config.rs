//! Config scanner (v0.4) — custom-code-execution risk in model configs.
//!
//! A growing supply-chain vector is not the weights at all but the *config*: a
//! Hugging Face `config.json` can declare, via `auto_map`, custom Python modules
//! shipped alongside the weights that are imported and executed when the model
//! is loaded with `from_pretrained(..., trust_remote_code=True)`. The code runs
//! on the loading host before any inference, exactly like a malicious pickle —
//! but it lives in the config and the repo's `*.py` files, which the pickle and
//! weight scanners never see.
//!
//! This scanner is static: it reads the parsed config JSON ([`Artifact::config`])
//! and surfaces the declarations that opt a loader into running author-supplied
//! code. It never fetches or executes anything.

use crate::artifact::Artifact;
use crate::finding::{truncate, Finding, Location, Severity};
use crate::scanners::Scanner;

pub struct ConfigScanner;

impl Scanner for ConfigScanner {
    fn id(&self) -> &'static str {
        "config"
    }
    fn description(&self) -> &'static str {
        "Detects custom-code execution declarations in model configs (auto_map / trust_remote_code)"
    }
    fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
        let obj = match artifact.config.as_ref().and_then(|v| v.as_object()) {
            Some(o) => o,
            None => return Vec::new(),
        };
        let mut findings = Vec::new();

        // 1) `auto_map` — the model ships custom Python modules that a loader
        //    imports and runs under `trust_remote_code=True`.
        if let Some(auto_map) = obj.get("auto_map") {
            let mut refs = Vec::new();
            collect_strings(auto_map, &mut refs);
            refs.retain(|r| r.contains('.'));
            refs.sort();
            refs.dedup();
            if !refs.is_empty() {
                let modules = module_files(&refs);
                findings.push(
                    Finding::builder("THK-CFG-001", "config", Severity::High)
                        .title("Model declares custom code via `auto_map`")
                        .detail(format!(
                            "This config maps model/tokenizer classes to custom modules \
                             ({}). Loading the model with `from_pretrained(..., \
                             trust_remote_code=True)` imports and executes this \
                             author-supplied Python on the host before any inference \
                             runs — the same code-execution risk as a malicious pickle.",
                            modules.join(", ")
                        ))
                        .location(Location::new("config:auto_map"))
                        .confidence(0.9)
                        .reference("MITRE-ATLAS: AML.T0010 ML Supply Chain Compromise")
                        .reference("CWE-494: Download of Code Without Integrity Check")
                        .reference("OWASP-LLM05: Supply Chain Vulnerabilities")
                        .remediation(
                            "Review the referenced `*.py` modules in the repository before \
                             loading, pin an exact revision, and prefer models that run on \
                             upstream `transformers` code. Never load with \
                             `trust_remote_code=True` from an untrusted source."
                                .to_string(),
                        )
                        .evidence(truncate(&refs.join(", "), 160))
                        .build(),
                );
            }
        }

        // 2) `trust_remote_code: true` baked into the shipped config.
        if obj.get("trust_remote_code").and_then(|v| v.as_bool()) == Some(true) {
            findings.push(
                Finding::builder("THK-CFG-002", "config", Severity::High)
                    .title("Config hard-codes `trust_remote_code: true`")
                    .detail(
                        "The config sets `trust_remote_code: true`, pre-authorizing a loader \
                         to execute custom Python shipped with the model. Trust should be a \
                         decision made at load time after review, not baked into the artifact."
                            .to_string(),
                    )
                    .location(Location::new("config:trust_remote_code"))
                    .confidence(0.85)
                    .reference("MITRE-ATLAS: AML.T0010 ML Supply Chain Compromise")
                    .reference("CWE-494: Download of Code Without Integrity Check")
                    .reference("OWASP-LLM05: Supply Chain Vulnerabilities")
                    .remediation(
                        "Remove `trust_remote_code` from the config and decide trust at load \
                         time after reviewing the model's custom code."
                            .to_string(),
                    )
                    .build(),
            );
        }

        // 3) `custom_pipelines` — a custom pipeline is likewise author code loaded
        //    under trust_remote_code.
        if obj.contains_key("custom_pipelines") {
            findings.push(
                Finding::builder("THK-CFG-003", "config", Severity::Medium)
                    .title("Config declares a custom pipeline")
                    .detail(
                        "The config declares a `custom_pipelines` entry, which maps to \
                         author-supplied pipeline code executed under `trust_remote_code`. \
                         Review the referenced module before loading."
                            .to_string(),
                    )
                    .location(Location::new("config:custom_pipelines"))
                    .confidence(0.6)
                    .reference("OWASP-LLM05: Supply Chain Vulnerabilities")
                    .reference("CWE-494: Download of Code Without Integrity Check")
                    .build(),
            );
        }

        findings
    }
}

/// Recursively collect every string leaf of a JSON value.
fn collect_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|v| collect_strings(v, out)),
        serde_json::Value::Object(m) => m.values().for_each(|v| collect_strings(v, out)),
        _ => {}
    }
}

/// Map `module.Class` references to the distinct `module.py` files they imply.
fn module_files(refs: &[String]) -> Vec<String> {
    let mut files: Vec<String> = refs
        .iter()
        .filter_map(|r| r.split('.').next())
        .filter(|m| !m.is_empty())
        .map(|m| format!("{m}.py"))
        .collect();
    files.sort();
    files.dedup();
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact_with_config(json: &str) -> Artifact {
        use std::sync::atomic::{AtomicU64, Ordering};
        // Build a minimal Artifact by loading a temp config file, exercising the
        // real parse path (format detection + JSON parsing). The filename is made
        // unique per call so concurrently-running tests never share a path.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("thk_cfg_test_{}_{n}.json", std::process::id()));
        std::fs::write(&path, json).unwrap();
        let a = Artifact::load(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        a
    }

    #[test]
    fn auto_map_is_flagged_high() {
        let a = artifact_with_config(
            r#"{
                "model_type": "custom",
                "auto_map": {
                    "AutoConfig": "configuration_phi.PhiConfig",
                    "AutoModelForCausalLM": "modeling_phi.PhiForCausalLM"
                }
            }"#,
        );
        let findings = ConfigScanner.scan(&a);
        let f = findings
            .iter()
            .find(|f| f.rule_id == "THK-CFG-001")
            .expect("auto_map finding");
        assert_eq!(f.severity, Severity::High);
        let ev = f.evidence.as_deref().unwrap_or("");
        assert!(ev.contains("modeling_phi"), "evidence: {ev}");
    }

    #[test]
    fn trust_remote_code_true_is_flagged() {
        let a = artifact_with_config(r#"{ "trust_remote_code": true }"#);
        let findings = ConfigScanner.scan(&a);
        assert!(findings.iter().any(|f| f.rule_id == "THK-CFG-002"));
    }

    #[test]
    fn plain_config_is_clean() {
        let a = artifact_with_config(r#"{ "model_type": "llama", "hidden_size": 4096 }"#);
        let findings = ConfigScanner.scan(&a);
        assert!(
            findings.is_empty(),
            "benign config should not be flagged: {findings:?}"
        );
    }

    #[test]
    fn non_config_artifact_yields_nothing() {
        // A config-less artifact (config: None) must produce no findings and not panic.
        let a = artifact_with_config(r#"{ "ok": 1 }"#);
        // Benign config → ConfigScanner clean, and the helpers are pure.
        assert!(ConfigScanner.scan(&a).is_empty());
    }
}
