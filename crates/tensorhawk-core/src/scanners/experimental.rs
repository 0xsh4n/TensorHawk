//! Experimental research detectors (v2.0) — **heuristic and probabilistic**.
//!
//! These detectors look for statistical anomalies that have been *correlated*
//! with backdoors/triggers and memorization in the literature. They are not
//! ground truth: a hit is a prompt to investigate, never proof, and a clean
//! result proves nothing. Everything here is gated behind `--experimental` and
//! every finding is capped at low confidence and labelled accordingly.

use crate::artifact::Artifact;
use crate::finding::{Finding, Location, Severity};
use crate::scanners::Scanner;

/// The set of experimental scanners, enabled only under `--experimental`.
pub fn experimental_scanners() -> Vec<Box<dyn Scanner>> {
    vec![Box::new(WeightOutlierScanner)]
}

/// Flags float tensors with extreme magnitude outliers — a pattern sometimes
/// associated with dedicated "trigger" neurons in backdoored models.
pub struct WeightOutlierScanner;

impl Scanner for WeightOutlierScanner {
    fn id(&self) -> &'static str {
        "experimental-weights"
    }
    fn description(&self) -> &'static str {
        "[experimental] Heuristic weight-magnitude outlier detector"
    }
    fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
        let mut findings = Vec::new();
        for t in &artifact.tensors {
            if !matches!(t.dtype.as_str(), "F32" | "f32") {
                continue;
            }
            let bytes = match artifact.tensor_bytes(t) {
                Some(b) if b.len() >= 4096 => b,
                _ => continue,
            };
            if let Some((mean_abs, max_abs)) = f32_stats(bytes) {
                // A single value ~1000x the mean magnitude is highly unusual for
                // trained weights and worth a look.
                if mean_abs > 0.0 && max_abs > mean_abs * 1000.0 {
                    findings.push(
                        Finding::builder("THK-EXP-001", "experimental-weights", Severity::Low)
                            .title("[experimental] Extreme weight-magnitude outlier")
                            .detail(format!(
                                "Tensor `{}` has a maximum |weight| of {:.3e} against a mean \
                                 |weight| of {:.3e} (ratio {:.0}x). Extreme outliers can be \
                                 benign, but have been associated with trigger neurons in \
                                 backdoored models. This is a heuristic signal, not proof.",
                                t.name,
                                max_abs,
                                mean_abs,
                                max_abs / mean_abs
                            ))
                            .location(Location::new(format!("tensor:{}", t.name)))
                            .confidence(0.25)
                            .reference("MITRE-ATLAS: AML.T0018 Backdoor ML Model")
                            .build(),
                    );
                }
            }
        }
        findings
    }
}

/// Mean and max of |x| over an f32 tensor, bounded work.
fn f32_stats(bytes: &[u8]) -> Option<(f32, f32)> {
    const MAX_ELEMS: usize = 8_000_000;
    let mut sum = 0f64;
    let mut max = 0f32;
    let mut n = 0u64;
    for chunk in bytes.chunks_exact(4).take(MAX_ELEMS) {
        let v = f32::from_le_bytes(chunk.try_into().unwrap());
        if v.is_finite() {
            let a = v.abs();
            sum += a as f64;
            if a > max {
                max = a;
            }
            n += 1;
        }
    }
    if n == 0 {
        None
    } else {
        Some(((sum / n as f64) as f32, max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_finds_outlier() {
        // Many tiny weights plus one large spike: max should dwarf the mean by
        // well over 1000x even after the spike nudges the mean up.
        let mut b = Vec::new();
        for _ in 0..5000 {
            b.extend_from_slice(&0.001f32.to_le_bytes());
        }
        b.extend_from_slice(&1000.0f32.to_le_bytes());
        let (mean, max) = f32_stats(&b).unwrap();
        assert!(max > mean * 1000.0, "mean={mean} max={max}");
    }
}
