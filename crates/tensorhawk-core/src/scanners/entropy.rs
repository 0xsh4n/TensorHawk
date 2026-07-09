//! Entropy-based anomaly detection.
//!
//! Slides a window over pickle streams (and other non-weight regions) looking
//! for blocks whose Shannon entropy is high enough to suggest a compressed or
//! encrypted payload — a common way to smuggle a second-stage blob past
//! signature scanners. Float weight regions are intentionally excluded because
//! quantized/random weights are legitimately high-entropy and would swamp the
//! signal with false positives.

use crate::artifact::Artifact;
use crate::finding::{Finding, Location, Severity};
use crate::scanners::Scanner;

pub struct EntropyScanner;

const WINDOW: usize = 4096;
const THRESHOLD: f64 = 7.5; // bits/byte; 8.0 is the theoretical max

fn shannon_entropy(block: &[u8]) -> f64 {
    if block.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in block {
        counts[b as usize] += 1;
    }
    let len = block.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

impl Scanner for EntropyScanner {
    fn id(&self) -> &'static str {
        "entropy"
    }
    fn description(&self) -> &'static str {
        "Flags high-entropy blobs that may hide compressed/encrypted payloads"
    }
    fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
        let mut findings = Vec::new();
        for stream in &artifact.pickles {
            let bytes = &stream.bytes;
            let mut off = 0;
            let mut flagged = false;
            while off + WINDOW <= bytes.len() {
                let h = shannon_entropy(&bytes[off..off + WINDOW]);
                if h >= THRESHOLD {
                    findings.push(
                        Finding::builder("THK-ENT-001", "entropy", Severity::Medium)
                            .title("High-entropy region inside pickle stream")
                            .detail(format!(
                                "A {WINDOW}-byte window at offset {off} has entropy {h:.2} \
                                 bits/byte, consistent with a compressed or encrypted payload \
                                 embedded in the object graph."
                            ))
                            .location(Location::at(&stream.name, off as u64))
                            .confidence(0.5)
                            .reference("MITRE-ATLAS: AML.T0010 ML Supply Chain Compromise")
                            .build(),
                    );
                    flagged = true;
                    break; // one report per stream is enough
                }
                off += WINDOW;
            }
            let _ = flagged;
        }
        findings
    }
}
