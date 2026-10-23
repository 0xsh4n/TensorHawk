<div align="center">

# 🦅 TensorHawk

**Static security analysis for AI model artifacts — know what's inside before you load it.**

*Semgrep and Trivy scan your source and containers. TensorHawk scans the weights.*

[![CI](https://github.com/0xsh4n/TensorHawk/actions/workflows/ci.yml/badge.svg)](https://github.com/0xsh4n/TensorHawk/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/0xsh4n/TensorHawk?sort=semver)](https://github.com/0xsh4n/TensorHawk/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

</div>

---

## Why

A model file is executable supply chain. Loading a PyTorch checkpoint with `torch.load`
runs whatever pickle opcodes it contains — including `os.system(...)` — *before* you
ever run inference. Beyond code execution, model artifacts routinely ship with leaked
API keys in their metadata, personal data baked into tokenizer configs, and build paths
that fingerprint internal infrastructure.

TensorHawk is a fast, **fully offline** static analyzer that inspects a model *artifact*
— the container, its metadata, and its serialized object graph — and reports security,
privacy, and provenance risks before the model reaches a runtime.

It does **not** execute the model, does **not** call the network, and does **not** need a GPU.

## What it catches today (v0.2)

| Scanner | Detects |
| --- | --- |
| `pickle` | Dangerous imports (`os`, `subprocess`, `ctypes`, `builtins.eval`, …) and `REDUCE`-based code execution in PyTorch pickle streams; truncated/evasive pickles |
| `secrets` | AWS / GitHub / Slack / Google / Stripe / OpenAI / Anthropic keys, private-key blocks, JWTs, DB connection strings |
| `pii` | Emails, credit cards (Luhn-validated), SSN, Aadhaar, PAN, IBAN leaked into metadata |
| `metadata` | Absolute build paths (username/host leaks), internal URLs, cloud/infra identifiers, provenance |
| `config` | Custom-code execution declared in model configs: Hugging Face `auto_map`, baked-in `trust_remote_code: true`, and `custom_pipelines` — the code `from_pretrained(trust_remote_code=True)` runs on load |
| `entropy` | High-entropy blobs hidden inside pickle object graphs (packed/encrypted second-stage payloads) |
| `weights` | Tensor shape × dtype byte-size mismatches, non-finite (NaN/Inf) weights, fully-zeroed and duplicate tensors, dtype/shape-overflow anomalies |
| `lineage` | LoRA / PEFT adapters, declared base model, quantization/conversion ancestry |
| `rules` | Declarative **MODEL_RULE** detections — including dangerous graph operators (TensorFlow `PyFunc` → arbitrary Python, file-I/O ops, custom-domain ONNX ops) and extra credential patterns |

**Formats:** GGUF · safetensors · PyTorch ZIP (`.bin`/`.pt`/`.pth`/`.ckpt`) · legacy pickle · **ONNX** · **TensorFlow** SavedModel/GraphDef · **MLX / NumPy `.npz`** (object arrays are routed to the pickle scanner) · **Hugging Face JSON configs** (`config.json`, `tokenizer_config.json`, `adapter_config.json`, … — config strings are also fed to the `secrets`/`pii`/`metadata` scanners).

Detections ship as **data**: the `MODEL_RULE` engine loads a bundled rule pack and any packs you pass with `--rules <dir>` — see [`docs/RULES.md`](docs/RULES.md) to write your own. Findings are scored by severity × confidence, mapped to **OWASP LLM Top 10**, **MITRE ATLAS**, and **CWE**, and can be emitted as **SARIF** for GitHub code scanning or a self-contained **HTML** report.

## Install

### From a release (recommended)

Download a prebuilt binary for your platform from the
[Releases page](https://github.com/0xsh4n/TensorHawk/releases), verify the checksum,
and drop it on your `PATH`:

```bash
# example for Linux x86_64
curl -LO https://github.com/0xsh4n/TensorHawk/releases/latest/download/tensorhawk-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/0xsh4n/TensorHawk/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar xzf tensorhawk-x86_64-unknown-linux-gnu.tar.gz
sudo mv tensorhawk /usr/local/bin/
```

### From source

```bash
cargo install --git https://github.com/0xsh4n/TensorHawk tensorhawk-cli
# or, in a clone:
cargo build --release   # -> target/release/tensorhawk
```

Requires Rust 1.75+.

## Usage

```bash
# scan a single model
tensorhawk model.safetensors

# scan a directory of models (recursively) and fail CI on high+ findings
tensorhawk ./models --recursive --fail-on high

# machine-readable output
tensorhawk model.bin --format json  > report.json
tensorhawk model.bin --format sarif > report.sarif
tensorhawk model.bin --format html  --output report.html

# only show medium and above
tensorhawk model.bin --min-severity medium

# load extra declarative rule packs
tensorhawk model.onnx --rules ./my-rules

# adopt on a noisy repo: capture a baseline, then fail only on NEW findings
tensorhawk ./models --recursive --write-baseline tensorhawk.baseline.json
tensorhawk ./models --recursive --baseline tensorhawk.baseline.json --fail-on high

# opt into experimental, heuristic research detectors (probabilistic)
tensorhawk model.safetensors --experimental
```

Example run against a booby-trapped checkpoint:

```
TensorHawk v0.2.0  —  malicious_model.bin
  format: pytorch-zip   size: 178 B   risk score: 62/100

  CRITICAL  Dangerous pickle import: posix.system  (97% conf)
           THK-PKL-001 · pickle · archive:archive/data.pkl
           evidence: GLOBAL posix.system

  1 critical  0 high  0 medium  0 low  0 info
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed; no finding at/above `--fail-on` (default `high`) |
| `1` | Completed; a finding at/above `--fail-on` was reported |
| `2` | No scannable artifact found at the given path |

## Use in CI (GitHub Actions)

```yaml
- name: Scan model artifacts
  run: |
    tensorhawk ./models --recursive --format sarif --output tensorhawk.sarif --fail-on high
- name: Upload to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: tensorhawk.sarif
```

## Architecture

```
                 ┌──────────────┐
   model file ──▶│  Artifact    │  mmap + format detection + structural parse
                 │  loader      │  (GGUF / safetensors / pickle streams / metadata)
                 └──────┬───────┘
                        │ &Artifact  (read-only, shared)
          ┌─────────────┼─────────────┬─────────────┬──────────────┐
          ▼             ▼             ▼             ▼              ▼
       pickle       secrets          pii         metadata       entropy      … plugins
          └─────────────┴──────┬──────┴─────────────┴──────────────┘
                               ▼
                      ┌──────────────┐
                      │   Report     │  severity × confidence → 0–100 risk score
                      │  (JSON /     │  OWASP LLM / MITRE ATLAS / CWE mapping
                      │  SARIF /     │
                      │  human)      │
                      └──────────────┘
```

Every scanner implements a single trait and is a **pure function of the artifact**, which
makes them independently testable, safely parallelizable, and the natural seam for
community plugins. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
tensorhawk/
├── crates/
│   ├── tensorhawk-core/     # engine: formats, scanners, findings, reports
│   │   └── src/
│   │       ├── scanners/    # pickle, secrets, pii, metadata, entropy,
│   │       │                #   weights, lineage, experimental
│   │       ├── rules/       # MODEL_RULE lexer + parser + engine
│   │       ├── pb.rs        # minimal protobuf reader (ONNX / TF)
│   │       └── baseline.rs  # finding suppression
│   └── tensorhawk-cli/      # `tensorhawk` binary
├── rules/                   # declarative rule packs (builtin.model_rule)
├── tests/fixtures/          # golden malicious/benign artifacts
└── .github/workflows/       # CI + multi-platform release automation
```

## Roadmap

TensorHawk ships a working core first and grows outward. This is deliberately honest about
what exists versus what's planned.

- **v0.1 — MVP (shipped):** pickle/secrets/pii/metadata/entropy scanners; GGUF, safetensors,
  PyTorch pickle; human/JSON/SARIF output; CI gate; multi-platform releases.
- **v0.2 — Rules & formats (shipped):** ONNX + TensorFlow + MLX/`.npz` parsing; the declarative
  `MODEL_RULE` engine with a bundled pack and `--rules`; graph-operator detections; parallel
  scanning; HTML report; `--baseline` suppression; merged SARIF.
- **v0.3 — Weights & lineage (shipped):** `weights` integrity scanner (shape/dtype/size,
  NaN/Inf, zeroed/duplicate tensors) and `lineage` scanner (LoRA/PEFT adapters, base model,
  quant/convert ancestry).
- **v0.4 — Scale & SDKs (partial):** parallel batch scanning and bounded memory shipped;
  streaming >100 GB, SIMD, and the Python SDK are still open.
- **v1.0 — Stable platform (partial):** fuzz-style robustness gates shipped; stable plugin ABI,
  signed rule packs, and reproducible-build attestation are still open.
- **v2.0 — Research detectors (experimental, partial):** a heuristic weight-outlier backdoor
  indicator ships behind `--experimental`; memorization/trigger signals are still open. Anything
  here is clearly labelled probabilistic and never presented as ground truth.

Full detail in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Scope and honest limitations

TensorHawk is a **static** analyzer. It reasons about bytes and structure, not runtime
behavior.

- It cannot prove a model is *safe* — only surface specific, evidenced risks.
- Backdoor/memorization detection is an open research problem; anything in that space will
  be clearly marked experimental and heuristic, never presented as ground truth.
- Secret/PII patterns favor precision but will miss novel formats and occasionally
  false-positive; every finding carries a confidence score and redacted evidence so you can
  triage quickly. Secrets are **never** emitted in full.

## Contributing

New scanners and rules are the highest-value contributions. A scanner is ~100 lines
implementing one trait — or you can add a detection with **no code at all** by writing a
[`MODEL_RULE`](docs/RULES.md) pack. Start with [`DEVELOPING.md`](DEVELOPING.md) for a
from-scratch build/run/test setup, then see [`CONTRIBUTING.md`](CONTRIBUTING.md),
[`docs/RULES.md`](docs/RULES.md), and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Security

To report a vulnerability in TensorHawk itself, see [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
