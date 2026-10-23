//! Weight-integrity scanner (v0.3).
//!
//! Trained weights should be internally consistent: the bytes a tensor occupies
//! must match the size implied by its declared shape and dtype, floating-point
//! values should be finite, and identical large tensors are unusual. This
//! scanner surfaces structural anomalies that indicate tampering, corruption, a
//! payload smuggled into a "weight", or a poisoned checkpoint — without ever
//! executing the model.
//!
//! Byte-exact checks run where the container gives an exact tensor layout
//! (safetensors); for GGUF/ONNX we validate the descriptors themselves.

use crate::artifact::Artifact;
use crate::finding::{Finding, Location, Severity};
use crate::scanners::Scanner;
use std::collections::HashMap;

pub struct WeightScanner;

/// Byte width of a safetensors dtype, if fixed-size.
fn dtype_size(dt: &str) -> Option<u64> {
    Some(match dt {
        "F64" | "I64" | "U64" | "f64" | "i64" | "u64" => 8,
        "F32" | "I32" | "U32" | "f32" | "i32" | "u32" => 4,
        "F16" | "BF16" | "I16" | "U16" | "f16" | "bf16" | "i16" | "u16" => 2,
        "I8" | "U8" | "BOOL" | "F8_E4M3" | "F8_E5M2" | "i8" | "u8" | "bool" => 1,
        _ => return None,
    })
}

/// True for standard GGUF/GGML block-quantized tensor dtypes. These are the
/// normal storage types of a quantized model (a `Q4_K_M` GGUF is almost entirely
/// `q4_k`/`q6_k`), so they are *recognized* — they simply have no fixed
/// per-element byte width, which is why [`dtype_size`] returns `None` for them.
fn is_quant_dtype(dt: &str) -> bool {
    matches!(
        dt,
        "q4_0"
            | "q4_1"
            | "q5_0"
            | "q5_1"
            | "q8_0"
            | "q8_1"
            | "q2_k"
            | "q3_k"
            | "q4_k"
            | "q5_k"
            | "q6_k"
            | "q8_k"
    )
}

fn shape_numel(shape: &[u64]) -> Option<u64> {
    shape.iter().try_fold(1u64, |acc, &d| acc.checked_mul(d))
}

impl Scanner for WeightScanner {
    fn id(&self) -> &'static str {
        "weights"
    }
    fn description(&self) -> &'static str {
        "Flags tensor shape/dtype/size inconsistencies and non-finite weights"
    }
    fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Fingerprints of large tensors, to spot duplicates.
        let mut seen: HashMap<u64, String> = HashMap::new();

        for t in &artifact.tensors {
            let comp = format!("tensor:{}", t.name);

            // 1) Descriptor sanity: known dtype, non-overflowing shape.
            //    GGUF/GGML quantized dtypes are known (just not fixed-width), so
            //    they are not flagged — otherwise every quantized tensor in a
            //    normal GGUF would produce a finding.
            if dtype_size(&t.dtype).is_none()
                && !is_quant_dtype(&t.dtype)
                && t.dtype != "string"
                && t.dtype != "?"
            {
                findings.push(
                    Finding::builder("THK-WGT-004", "weights", Severity::Info)
                        .title(format!("Unrecognized tensor dtype `{}`", t.dtype))
                        .detail(format!(
                            "Tensor `{}` declares dtype `{}`, which is not a known \
                             weight dtype. Review the container header.",
                            t.name, t.dtype
                        ))
                        .location(Location::new(&comp))
                        .confidence(0.4)
                        .build(),
                );
            }
            if shape_numel(&t.shape).is_none() {
                findings.push(
                    Finding::builder("THK-WGT-005", "weights", Severity::Medium)
                        .title("Tensor shape overflows")
                        .detail(format!(
                            "Tensor `{}` declares a shape whose element count overflows \
                             64 bits — a hostile header can use this to trigger integer \
                             overflow in a naive loader.",
                            t.name
                        ))
                        .location(Location::new(&comp))
                        .confidence(0.7)
                        .reference("CWE-190: Integer Overflow or Wraparound")
                        .build(),
                );
            }

            // 2) Byte-exact checks (safetensors): size, finiteness, zero/dupe.
            let bytes = match artifact.tensor_bytes(t) {
                Some(b) => b,
                None => continue,
            };

            if let (Some(elem), Some(numel)) = (dtype_size(&t.dtype), shape_numel(&t.shape)) {
                if let Some(expected) = elem.checked_mul(numel) {
                    if expected != bytes.len() as u64 {
                        findings.push(
                            Finding::builder("THK-WGT-001", "weights", Severity::High)
                                .title("Tensor byte size inconsistent with shape × dtype")
                                .detail(format!(
                                    "Tensor `{}` ({}, shape {:?}) should occupy {} bytes but \
                                     the header allocates {}. A mismatch can hide extra data \
                                     inside a declared weight or crash a loader.",
                                    t.name,
                                    t.dtype,
                                    t.shape,
                                    expected,
                                    bytes.len()
                                ))
                                .location(Location::new(&comp))
                                .confidence(0.85)
                                .reference("MITRE-ATLAS: AML.T0010 ML Supply Chain Compromise")
                                .reference("CWE-1284: Improper Validation of Specified Quantity")
                                .build(),
                        );
                    }
                }
            }

            let nonfinite = count_nonfinite(&t.dtype, bytes);
            if nonfinite > 0 {
                findings.push(
                    Finding::builder("THK-WGT-002", "weights", Severity::Medium)
                        .title("Non-finite values (NaN/Inf) in weights")
                        .detail(format!(
                            "Tensor `{}` contains {} non-finite ({}) value(s). This corrupts \
                             inference and can be an artifact of poisoning or truncation.",
                            t.name, nonfinite, t.dtype
                        ))
                        .location(Location::new(&comp))
                        .confidence(0.8)
                        .build(),
                );
            }

            // Only bother with zero/dupe checks on non-trivial tensors.
            if bytes.len() >= 4096 {
                if bytes.iter().all(|&b| b == 0) {
                    findings.push(
                        Finding::builder("THK-WGT-003", "weights", Severity::Low)
                            .title("Fully zeroed weight tensor")
                            .detail(format!(
                                "Tensor `{}` ({} bytes) is entirely zero. Occasionally \
                                 legitimate (uninitialised bias) but can mark a disabled or \
                                 placeholder layer worth reviewing.",
                                t.name,
                                bytes.len()
                            ))
                            .location(Location::new(&comp))
                            .confidence(0.5)
                            .build(),
                    );
                } else {
                    let fp = fnv1a(bytes);
                    if let Some(other) = seen.get(&fp) {
                        findings.push(
                            Finding::builder("THK-WGT-006", "weights", Severity::Info)
                                .title("Duplicate weight tensor")
                                .detail(format!(
                                    "Tensor `{}` is byte-identical to `{}`. Cloned weights can \
                                     indicate a botched merge or padding.",
                                    t.name, other
                                ))
                                .location(Location::new(&comp))
                                .confidence(0.6)
                                .build(),
                        );
                    } else {
                        seen.insert(fp, t.name.clone());
                    }
                }
            }
        }

        findings
    }
}

/// Count NaN/Inf values in a float tensor's bytes (bounded work per tensor).
fn count_nonfinite(dtype: &str, bytes: &[u8]) -> usize {
    const MAX_ELEMS: usize = 4_000_000;
    let mut n = 0usize;
    match dtype {
        "F32" | "f32" => {
            for chunk in bytes.chunks_exact(4).take(MAX_ELEMS) {
                let v = f32::from_le_bytes(chunk.try_into().unwrap());
                if !v.is_finite() {
                    n += 1;
                }
            }
        }
        "F64" | "f64" => {
            for chunk in bytes.chunks_exact(8).take(MAX_ELEMS) {
                let v = f64::from_le_bytes(chunk.try_into().unwrap());
                if !v.is_finite() {
                    n += 1;
                }
            }
        }
        "F16" | "f16" => {
            for chunk in bytes.chunks_exact(2).take(MAX_ELEMS) {
                let bits = u16::from_le_bytes(chunk.try_into().unwrap());
                // exponent all ones => Inf/NaN
                if bits & 0x7C00 == 0x7C00 {
                    n += 1;
                }
            }
        }
        "BF16" | "bf16" => {
            for chunk in bytes.chunks_exact(2).take(MAX_ELEMS) {
                let bits = u16::from_le_bytes(chunk.try_into().unwrap());
                if bits & 0x7F80 == 0x7F80 {
                    n += 1;
                }
            }
        }
        _ => {}
    }
    n
}

/// 64-bit FNV-1a, used only as a fast content fingerprint for dup detection.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_helpers() {
        assert_eq!(dtype_size("F32"), Some(4));
        assert_eq!(shape_numel(&[2, 3, 4]), Some(24));
        assert_eq!(shape_numel(&[u64::MAX, 2]), None);
    }

    #[test]
    fn gguf_quant_dtypes_are_recognized() {
        // The storage types of a normal quantized GGUF — must not be flagged as
        // "unrecognized" (they just lack a fixed per-element width).
        for dt in ["q4_0", "q4_k", "q5_k", "q6_k", "q8_0"] {
            assert!(is_quant_dtype(dt), "{dt} should be a known quant dtype");
            assert_eq!(dtype_size(dt), None);
        }
        assert!(!is_quant_dtype("f32"));
        assert!(!is_quant_dtype("ggml_unknown"));
    }

    #[test]
    fn detects_nonfinite_f32() {
        // two f32: 1.0 and +Inf
        let mut b = Vec::new();
        b.extend_from_slice(&1.0f32.to_le_bytes());
        b.extend_from_slice(&f32::INFINITY.to_le_bytes());
        assert_eq!(count_nonfinite("F32", &b), 1);
        // f16 +Inf is exponent-all-ones
        assert_eq!(count_nonfinite("F16", &0x7C00u16.to_le_bytes()), 1);
    }
}
