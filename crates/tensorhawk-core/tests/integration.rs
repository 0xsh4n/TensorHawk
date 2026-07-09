//! End-to-end tests over the checked-in fixture artifacts.

use std::path::PathBuf;
use tensorhawk_core::{analyze, Severity};

fn fixture(name: &str) -> PathBuf {
    // crate dir -> ../../tests/fixtures
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn malicious_checkpoint_is_critical() {
    let report = analyze(&fixture("malicious_model.bin")).expect("scan");
    assert_eq!(report.worst(), Some(Severity::Critical));
    assert!(report
        .findings
        .iter()
        .any(|f| f.scanner == "pickle" && f.severity == Severity::Critical));
    assert!(report.risk_score >= 50);
}

#[test]
fn benign_checkpoint_is_clean() {
    let report = analyze(&fixture("benign_model.bin")).expect("scan");
    assert!(report.findings.iter().all(|f| f.severity < Severity::High));
}

#[test]
fn leaky_safetensors_flags_aws_key() {
    let report = analyze(&fixture("leaky.safetensors")).expect("scan");
    assert!(report
        .findings
        .iter()
        .any(|f| f.rule_id == "THK-SEC-001" && f.severity == Severity::Critical));
    // Evidence must be redacted, never the full key.
    let sec = report
        .findings
        .iter()
        .find(|f| f.rule_id == "THK-SEC-001")
        .unwrap();
    assert!(sec.evidence.as_ref().unwrap().contains('…'));
}

#[test]
fn gguf_metadata_is_parsed() {
    let report = analyze(&fixture("model.gguf")).expect("scan");
    assert_eq!(report.format, "gguf");
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-MET-000"));
}
