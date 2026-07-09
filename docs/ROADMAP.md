# Roadmap

Versioned milestones from MVP to industry-standard. Dates are directional; scope is
the commitment.

## v0.1 — MVP (shipped)
- Formats: GGUF, safetensors, PyTorch ZIP, legacy pickle.
- Scanners: pickle, secrets, pii, metadata, entropy.
- Risk scoring + OWASP LLM / MITRE ATLAS / CWE mapping.
- Output: human, JSON, SARIF. CLI with `--fail-on` CI gate.
- Multi-platform release automation with checksums.

## v0.2 — Rules & formats
- ONNX (protobuf), TensorFlow SavedModel, MLX parsing.
- Runtime `MODEL_RULE` engine + parser; bundled rule pack; `--rules <dir>`.
- Parallel scanning (rayon) across scanners and files.
- HTML report; `--baseline` to suppress known findings.

## v0.3 — Weights & lineage
- Weight-integrity scanner: shape/dtype anomalies, tensor entropy outliers,
  duplicate/zeroed tensors, hash validation.
- LoRA / QLoRA / PEFT adapter detection and lineage.
- Supply-chain graph: conversion/quantization ancestry from metadata.

## v0.4 — Scale & SDKs
- Streaming analysis for >100 GB artifacts (windowed reads, no full load).
- SIMD-accelerated entropy + multi-pattern matching (AVX2/AVX-512).
- Python SDK (`pip install tensorhawk`) and Rust SDK docs.
- REST API server mode + interactive TUI.

## v1.0 — Stable platform
- Stable plugin ABI + Plugin SDK; out-of-tree scanners.
- Signed rule packs; reproducible-build attestation for releases.
- Golden corpus + fuzzing in CI as release gates.

## v2.0 — Research detectors (experimental)
- Heuristic backdoor/trigger indicators, memorization/membership signals.
- All shipped behind `--experimental`, clearly labelled as probabilistic, never
  presented as ground truth.
