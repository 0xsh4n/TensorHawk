# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-08-06
### Added
- **Formats:** ONNX (protobuf), TensorFlow SavedModel/GraphDef (protobuf), and
  NumPy/MLX `.npz` parsing. Object-dtype `.npy` arrays (which pickle their
  elements) are routed to the pickle scanner.
- **`MODEL_RULE` engine:** a hand-written lexer + recursive-descent/Pratt parser
  for the declarative rule language, a `RuleScanner` that evaluates rules as a
  pure function of the artifact, and a bundled reference rule pack. Load extra
  packs with `--rules <dir>`.
- **`operators` detections:** dangerous graph operators — TensorFlow `PyFunc`
  family (arbitrary Python, critical), file-I/O ops, and custom-domain ONNX
  operators — shipped as declarative rules.
- **Weight-integrity scanner (`weights`):** shape × dtype byte-size mismatches,
  non-finite (NaN/Inf) weights, fully-zeroed and duplicate tensors, dtype and
  shape-overflow anomalies.
- **Lineage scanner (`lineage`):** LoRA/PEFT adapter detection, declared base
  model, and quantization/conversion ancestry.
- **Parallel scanning** across scanners and files (rayon).
- **HTML report** (`--format html`) — self-contained, theme-aware.
- **Baseline suppression:** `--baseline <file>` to suppress known findings and
  `--write-baseline <file>` to capture the current set.
- **Experimental detectors** behind `--experimental`: a heuristic weight-outlier
  backdoor indicator, clearly labelled as probabilistic.
- Merged SARIF across multiple targets in a directory scan.
- Fuzz-style robustness tests for the pickle disassembler and rule parser.

## [0.1.0] - 2026-01-01
### Added
- Initial public release.
- Artifact loader with mmap and format detection for GGUF, safetensors,
  PyTorch ZIP, and legacy pickle.
- Scanners: `pickle` (dangerous-import / REDUCE code-execution detection),
  `secrets`, `pii` (Luhn-validated), `metadata`, `entropy`.
- Severity × confidence risk scoring (0–100) with OWASP LLM / MITRE ATLAS / CWE
  mapping.
- Output formats: human (ANSI), JSON, SARIF 2.1.0.
- CLI with directory walking, `--min-severity`, and a `--fail-on` CI gate.
- Cross-platform release automation (Linux gnu/musl, macOS x86_64/arm64, Windows)
  with SHA256 checksums.

[Unreleased]: https://github.com/0xsh4n/TensorHawk/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/0xsh4n/TensorHawk/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/0xsh4n/TensorHawk/releases/tag/v0.1.0
