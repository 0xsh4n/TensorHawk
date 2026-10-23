//! End-to-end tests over the checked-in fixture artifacts.

use std::path::PathBuf;
use tensorhawk_core::{analyze, Baseline, Severity};

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

#[test]
fn onnx_custom_operator_and_token_flagged() {
    let report = analyze(&fixture("model.onnx")).expect("scan");
    assert_eq!(report.format, "onnx");
    // Custom-domain operator via the declarative rule engine.
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-OPS-003"));
    // Hugging Face token embedded in metadata, matched by a MODEL_RULE.
    let hf = report
        .findings
        .iter()
        .find(|f| f.rule_id == "THK-SEC-020")
        .expect("hf token finding");
    assert_eq!(hf.severity, Severity::High);
    // Rule-engine evidence for credential surfaces must be redacted, never the
    // full secret.
    let ev = hf.evidence.as_ref().unwrap();
    assert!(ev.contains('…'), "evidence should be redacted: {ev}");
    assert!(!ev.contains("AAAAAAAAAAAAAAAA"), "full token leaked: {ev}");
}

#[test]
fn tensorflow_pyfunc_is_critical() {
    let report = analyze(&fixture("tf_pyfunc.pb")).expect("scan");
    assert_eq!(report.format, "tensorflow");
    assert!(report
        .findings
        .iter()
        .any(|f| f.rule_id == "THK-OPS-001" && f.severity == Severity::Critical));
}

#[test]
fn npz_object_array_routes_to_pickle_scanner() {
    let report = analyze(&fixture("object_array.npz")).expect("scan");
    assert_eq!(report.format, "npz");
    // The pickled object array reduces to os.system → critical pickle finding.
    assert_eq!(report.worst(), Some(Severity::Critical));
    assert!(report
        .findings
        .iter()
        .any(|f| f.scanner == "pickle" && f.severity == Severity::Critical));
}

#[test]
fn safetensors_weight_and_lineage_signals() {
    let report = analyze(&fixture("adapter.safetensors")).expect("scan");
    assert_eq!(report.format, "safetensors");
    // Weight-integrity: byte-size mismatch and a non-finite value.
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-WGT-001"));
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-WGT-002"));
    // Lineage: LoRA adapter, declared base model, quantization ancestry.
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-LIN-001"));
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-LIN-002"));
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-LIN-003"));
}

#[test]
fn baseline_suppresses_known_findings() {
    let report = analyze(&fixture("malicious_model.bin")).expect("scan");
    assert!(!report.findings.is_empty());
    // A baseline built from this report should suppress every finding.
    let baseline = Baseline::from_reports(std::slice::from_ref(&report));
    let mut again = analyze(&fixture("malicious_model.bin")).expect("scan");
    let suppressed = baseline.apply(&mut again);
    assert_eq!(suppressed, report.findings.len());
    assert!(again.findings.is_empty());
    assert_eq!(again.risk_score, 0);
}

#[test]
fn hf_config_flags_remote_code_execution() {
    let report = analyze(&fixture("config.json")).expect("scan");
    assert_eq!(report.format, "hf-config");
    // auto_map custom-code declaration and the baked-in trust_remote_code flag.
    let auto = report
        .findings
        .iter()
        .find(|f| f.rule_id == "THK-CFG-001")
        .expect("auto_map finding");
    assert_eq!(auto.severity, Severity::High);
    assert!(auto
        .evidence
        .as_deref()
        .is_some_and(|e| e.contains("modeling_custom")));
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-CFG-002"));
    // Flattening config strings into metadata lets the metadata scanner catch
    // the absolute build path leaked in `_name_or_path`.
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-MET-001"));
}

#[test]
fn csv_dataset_structure_pii_and_poisoning() {
    let report = analyze(&fixture("dataset.csv")).expect("scan");
    assert_eq!(report.format, "csv");
    // Structure readout.
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-DS-000"));
    // PII attributed to columns.
    assert!(report
        .findings
        .iter()
        .any(|f| f.rule_id == "THK-DS-010" && f.location.component.contains("email")));
    assert!(report
        .findings
        .iter()
        .any(|f| f.rule_id == "THK-DS-012" && f.location.component.contains("ssn")));
    // Poisoning / prompt-injection indicator and hidden-Unicode indicator.
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-DS-001"));
    assert!(report.findings.iter().any(|f| f.rule_id == "THK-DS-002"));
    // PII evidence must be redacted, never the raw SSN.
    let ssn = report
        .findings
        .iter()
        .find(|f| f.rule_id == "THK-DS-012")
        .unwrap();
    assert!(!ssn
        .evidence
        .as_deref()
        .unwrap_or("")
        .contains("123-45-6789"));
}

#[test]
fn html_report_is_self_contained() {
    let report = analyze(&fixture("malicious_model.bin")).expect("scan");
    let html = report.to_html();
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("TensorHawk"));
    // No external resource references (fully offline / self-contained).
    assert!(!html.contains("http://"));
    assert!(!html.contains("src=\"http"));
}
