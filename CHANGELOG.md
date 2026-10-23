# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [2.1.0] - 2026-10-23
### Fixed
- **GGUF quantized tensors no longer flood the report.** Standard GGUF/GGML
  block-quantized dtypes (`q4_0`, `q4_k`, `q5_k`, `q6_k`, `q8_0`, …) are now
  recognized, so a normal quantized model (e.g. a `Q4_K_M` GGUF) is no longer
  flagged with one "unrecognized tensor dtype" finding per tensor.

### Changed
- Faster raw secret scanning on large artifacts: a single `RegexSet` pass finds
  which patterns are present, and only those are re-scanned — a clean multi-GB
  model now costs one pass instead of one per pattern. No change to findings.
- Internal cleanup: shared `truncate`/`luhn_ok` helpers consolidated into
  `finding`; duplicated SARIF result construction and dead code removed.

## [2.0.0] - 2026-10-23
### Added
- **Professional HTML/PDF assessment reports.** The report is a formal,
  bicolor (navy / light-blue on white) security-assessment document: a cover
  with a TensorHawk wordmark and a *Prepared by / Date / Tool / Scope* block, an
  **Executive Summary** with a derived overall-risk posture, a **Methodology**
  note, and **Detailed Findings**. Each finding leads with its **public
  framework classification** — MITRE ATLAS, OWASP Top 10 for LLM Applications,
  and CWE — rendered as chips; the internal `THK-` code is demoted to a small
  "Detection ID". Findings carry full detail, redacted evidence, remediation,
  and references. A new **`--format pdf`** converts the same print-ready
  document to a paginated PDF via a local converter (WeasyPrint preferred, then
  wkhtmltopdf or headless Chromium/Chrome), with a running header and a footer
  carrying the author and `Page N of M`. `pdf` requires `--output`; with no
  converter installed it fails with guidance (optional integration, no new Rust
  dependency). New `--author <NAME>` flag (default `0xsh4n`; `--author ""`
  omits the byline).
- **Dataset analysis (`dataset` scanner):** CSV / TSV / JSONL are now recognized
  artifact formats. From a bounded sample the scanner reconstructs the dataset's
  **structure** (columns + inferred types, row count), and statically flags
  **PII** in content attributed to the column (email / SSN / Luhn-valid card /
  IP), **prompt-injection & data-poisoning indicators** (instruction-override
  phrasing; mapped to OWASP-LLM01 and MITRE ATLAS AML.T0020), **hidden/obfuscated
  Unicode** (zero-width and bidirectional "Trojan Source" characters), and
  **embedded active-content markup**. Indicators are labelled probabilistic; PII
  evidence is redacted.
- **Extensionless model discovery:** directory scans now identify model files by
  container magic (GGUF/GGML/ZIP/safetensors) in addition to file extension, so
  **Ollama's `sha256-<hash>` blobs** (and other extensionless artifacts) are
  picked up instead of being silently skipped. The sniff uses only strong,
  unambiguous magics to avoid over-matching arbitrary files.
- **Hugging Face JSON config parsing:** `config.json`, `tokenizer_config.json`,
  `adapter_config.json`, `model_index.json` and other `.json` config documents
  are now a recognized artifact format (`hf-config`). Config string values are
  flattened into artifact metadata, so the existing `secrets`/`pii`/`metadata`
  scanners inspect them too (leaked keys and build paths in configs are common).
  Parsing is bounded (16 MiB cap, capped key count and value length).
- **`config` scanner:** flags custom-code execution declared in model configs —
  Hugging Face `auto_map` (ships custom `*.py` modules run under
  `trust_remote_code=True`), a baked-in `trust_remote_code: true`, and
  `custom_pipelines`. These execute author-supplied Python on the loading host
  before inference, the same code-execution risk class as a malicious pickle.
  Mapped to MITRE ATLAS AML.T0010, CWE-494, and OWASP-LLM05. Still fully static:
  nothing is fetched or executed.

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

[Unreleased]: https://github.com/0xsh4n/TensorHawk/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/0xsh4n/TensorHawk/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/0xsh4n/TensorHawk/compare/v0.2.0...v2.0.0
[0.2.0]: https://github.com/0xsh4n/TensorHawk/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/0xsh4n/TensorHawk/releases/tag/v0.1.0
