<div align="center">

# 🦅 TensorHawk

**Static security analysis for AI model artifacts — know what's inside before you load it.**

*Semgrep and Trivy scan your source and containers. TensorHawk scans the weights.*

[![CI](https://github.com/your-org/tensorhawk/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/tensorhawk/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/your-org/tensorhawk?sort=semver)](https://github.com/your-org/tensorhawk/releases)
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

## What it catches today (v0.1)

| Scanner | Detects |
| --- | --- |
| `pickle` | Dangerous imports (`os`, `subprocess`, `ctypes`, `builtins.eval`, …) and `REDUCE`-based code execution in PyTorch pickle streams; truncated/evasive pickles |
| `secrets` | AWS / GitHub / Slack / Google / Stripe / OpenAI / Anthropic keys, private-key blocks, JWTs, DB connection strings |
| `pii` | Emails, credit cards (Luhn-validated), SSN, Aadhaar, PAN, IBAN leaked into metadata |
| `metadata` | Absolute build paths (username/host leaks), internal URLs, cloud/infra identifiers, provenance |
| `entropy` | High-entropy blobs hidden inside pickle object graphs (packed/encrypted second-stage payloads) |

**Formats:** GGUF · safetensors · PyTorch ZIP (`.bin`/`.pt`/`.pth`/`.ckpt`) · legacy pickle. ONNX / TF / MLX parsing is on the roadmap.

Findings are scored by severity × confidence, mapped to **OWASP LLM Top 10**, **MITRE ATLAS**, and **CWE**, and can be emitted as **SARIF** for GitHub code scanning.

## Install

### From a release (recommended)

Download a prebuilt binary for your platform from the
[Releases page](https://github.com/your-org/tensorhawk/releases), verify the checksum,
and drop it on your `PATH`:

```bash
# example for Linux x86_64
curl -LO https://github.com/your-org/tensorhawk/releases/latest/download/tensorhawk-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/your-org/tensorhawk/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
tar xzf tensorhawk-x86_64-unknown-linux-gnu.tar.gz
sudo mv tensorhawk /usr/local/bin/
```

### From source

```bash
cargo install --git https://github.com/your-org/tensorhawk tensorhawk-cli
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

# only show medium and above
tensorhawk model.bin --min-severity medium
```

Example run against a booby-trapped checkpoint:

```
TensorHawk v0.1.0  —  malicious_model.bin
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
│   │   └── src/scanners/    # pickle, secrets, pii, metadata, entropy
│   └── tensorhawk-cli/      # `tensorhawk` binary
├── rules/                   # declarative rule packs (roadmap: full rule language)
├── tests/fixtures/          # golden malicious/benign artifacts
└── .github/workflows/       # CI + multi-platform release automation
```

## Roadmap

TensorHawk ships a working core first and grows outward. This is deliberately honest about
what exists versus what's planned.

- **v0.1 — MVP (shipped):** pickle/secrets/pii/metadata/entropy scanners; GGUF, safetensors,
  PyTorch pickle; human/JSON/SARIF output; CI gate; multi-platform releases.
- **v0.2:** ONNX + TensorFlow + MLX parsing; declarative `MODEL_RULE` language with a parser
  and a bundled rule pack; parallel scanning across scanners and files; HTML report.
- **v0.3:** weight-integrity scanner (tensor shape/dtype/entropy anomalies, hash validation);
  LoRA/adapter lineage; supply-chain/ancestry graph.
- **v0.4:** streaming analysis for >100 GB artifacts without full load; SIMD-accelerated
  regex/entropy; Python SDK (`pip install tensorhawk`).
- **v1.0:** stable plugin ABI + Plugin SDK; signed rule packs; reproducible-build attestation.
- **v2.0:** optional ML-assisted detectors (backdoor/trigger heuristics, memorization
  indicators) behind a clearly-labelled `--experimental` flag.

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
implementing one trait. Start with [`DEVELOPING.md`](DEVELOPING.md) for a from-scratch
build/run/test setup, then see [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Security

To report a vulnerability in TensorHawk itself, see [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
