# Roadmap

Versioned milestones from MVP to industry-standard. Dates are directional; scope is
the commitment.

## v0.1 — MVP (shipped)
- Formats: GGUF, safetensors, PyTorch ZIP, legacy pickle.
- Scanners: pickle, secrets, pii, metadata, entropy.
- Risk scoring + OWASP LLM / MITRE ATLAS / CWE mapping.
- Output: human, JSON, SARIF. CLI with `--fail-on` CI gate.
- Multi-platform release automation with checksums.

## v0.2 — Rules & formats (shipped)
- ONNX (protobuf), TensorFlow SavedModel/GraphDef, MLX/NumPy `.npz` parsing.
- Runtime `MODEL_RULE` engine + parser; bundled rule pack; `--rules <dir>`.
- Declarative `operators` detections (TF `PyFunc`, file I/O, custom ONNX ops).
- Parallel scanning (rayon) across scanners and files.
- HTML report; `--baseline` / `--write-baseline` to manage known findings.
- Merged SARIF for directory scans.

## v0.3 — Weights & lineage (shipped)
- Weight-integrity scanner: shape × dtype byte-size mismatch, non-finite
  (NaN/Inf) weights, zeroed/duplicate tensors, dtype & shape-overflow anomalies.
- LoRA / QLoRA / PEFT adapter detection.
- Supply-chain lineage: declared base model and conversion/quantization
  ancestry from metadata.
- *Still open:* content-hash validation against a manifest; a full ancestry
  graph across multiple artifacts.

## v0.3.x — Config & custom-code surface (shipped)
- Hugging Face JSON configs (`config.json`, `tokenizer_config.json`, …) are a
  recognized `hf-config` format; string leaves are flattened into metadata so the
  `secrets`/`pii`/`metadata` scanners inspect config values.
- `config` scanner: `auto_map`, baked-in `trust_remote_code: true`, and
  `custom_pipelines` — custom author Python executed on load under
  `trust_remote_code=True`, the same code-execution class as a malicious pickle.
- *Still open:* correlate `auto_map` module references with the actual `*.py`
  files in a scanned model directory and flag/triage that custom code directly.

## v0.4 — Scale & SDKs (partial)
- **Done:** parallel batch scanning; mmap keeps multi-GB files off the heap; the
  secrets/rule passes are byte-range capped so hostile sizes can't exhaust
  memory.
- *Open:* windowed streaming for >100 GB single artifacts; SIMD-accelerated
  entropy + aho-corasick multi-pattern matching; Python SDK
  (`pip install tensorhawk`); REST server mode + interactive TUI.

## v1.0 — Stable platform (partial)
- **Done:** fuzz-style robustness gates for the pickle disassembler and rule
  parser (no panics on arbitrary input); `panic = "abort"`.
- *Open:* stable C-ABI plugin interface + Plugin SDK; signed rule packs;
  reproducible-build attestation; a golden corpus + `cargo fuzz` in CI.

## v2.0 — Research detectors (experimental, partial)
- **Done:** heuristic weight-magnitude outlier detector (a backdoor/trigger
  indicator) behind `--experimental`, capped at low confidence and labelled
  probabilistic.
- *Open:* memorization/membership-inference signals; trigger-pattern search.
- Everything here stays behind `--experimental`, clearly labelled, and is never
  presented as ground truth.
