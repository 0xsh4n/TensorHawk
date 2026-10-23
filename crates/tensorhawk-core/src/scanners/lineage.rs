//! Adapter / lineage scanner (v0.3).
//!
//! Surfaces supply-chain provenance so an operator can answer "where did this
//! artifact come from, and what is layered on top of it?" — LoRA/PEFT adapters,
//! quantization/conversion ancestry, and the declared base model. These are
//! informational signals (an adapter is not itself a vulnerability), but they
//! are exactly what you need when triaging a finding or auditing a model's
//! chain of custody.

use crate::artifact::Artifact;
use crate::finding::{truncate, Finding, Location, Severity};
use crate::scanners::Scanner;

pub struct LineageScanner;

impl LineageScanner {
    pub fn new() -> Self {
        LineageScanner
    }
}

impl Default for LineageScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Substrings in tensor names that mark a LoRA / adapter delta.
const ADAPTER_MARKERS: &[&str] = &[
    "lora_a",
    "lora_b",
    "lora_up",
    "lora_down",
    "lora_embedding",
    "lora.up",
    "lora.down",
    ".lora_",
    "adapter_",
    "ia3_",
    "dora_",
];

impl Scanner for LineageScanner {
    fn id(&self) -> &'static str {
        "lineage"
    }
    fn description(&self) -> &'static str {
        "Detects LoRA/PEFT adapters and conversion/quantization ancestry"
    }
    fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
        let mut findings = Vec::new();

        // 1) Adapter tensors by naming convention.
        let adapter_hits = artifact
            .tensors
            .iter()
            .filter(|t| {
                let n = t.name.to_ascii_lowercase();
                ADAPTER_MARKERS.iter().any(|m| n.contains(m))
            })
            .count();
        if adapter_hits > 0 {
            findings.push(
                Finding::builder("THK-LIN-001", "lineage", Severity::Info)
                    .title("LoRA / adapter weights present")
                    .detail(format!(
                        "{adapter_hits} tensor(s) follow LoRA/PEFT adapter naming. This \
                         artifact layers a fine-tuned delta on a base model; audit the \
                         adapter's provenance separately from the base."
                    ))
                    .location(Location::new("tensors"))
                    .confidence(0.85)
                    .reference("OWASP-LLM05: Supply Chain Vulnerabilities")
                    .build(),
            );
        }

        // 2) Declared base model / PEFT config (lineage link).
        for (key, value) in &artifact.metadata {
            let k = key.to_ascii_lowercase();
            if k.contains("base_model") || k == "onnx.meta.base_model" {
                findings.push(
                    Finding::builder("THK-LIN-002", "lineage", Severity::Info)
                        .title("Declared base model")
                        .detail(format!(
                            "Metadata field `{key}` records the base model this artifact \
                             derives from. Verify the base is a trusted source."
                        ))
                        .location(Location::new(format!("metadata:{key}")))
                        .confidence(0.9)
                        .evidence(truncate(value, 80))
                        .build(),
                );
            }
        }

        // 3) Quantization / conversion ancestry.
        if let Some((tool, key)) = detect_conversion(artifact) {
            findings.push(
                Finding::builder("THK-LIN-003", "lineage", Severity::Info)
                    .title("Quantization / conversion ancestry")
                    .detail(format!(
                        "Metadata indicates this artifact was produced by a conversion or \
                         quantization step ({tool}). Re-scan the pre-conversion source; \
                         conversion can strip or introduce risks."
                    ))
                    .location(Location::new(format!("metadata:{key}")))
                    .confidence(0.7)
                    .reference("OWASP-LLM05: Supply Chain Vulnerabilities")
                    .build(),
            );
        }

        findings
    }
}

/// Detect a conversion/quantization signal, returning `(tool, metadata_key)`.
fn detect_conversion(artifact: &Artifact) -> Option<(String, String)> {
    const TOOLS: &[(&str, &str)] = &[
        ("gptq", "GPTQ"),
        ("awq", "AWQ"),
        ("bitsandbytes", "bitsandbytes"),
        ("quantization", "quantization"),
        ("quantized", "quantization"),
        ("converted", "conversion"),
        ("convert", "conversion"),
        ("llama.cpp", "llama.cpp"),
        ("ggml", "GGML/GGUF conversion"),
    ];
    for (key, value) in &artifact.metadata {
        let hay = format!("{key} {value}").to_ascii_lowercase();
        for (needle, tool) in TOOLS {
            if hay.contains(needle) {
                return Some((tool.to_string(), key.clone()));
            }
        }
    }
    None
}
