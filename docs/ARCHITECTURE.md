# TensorHawk Architecture

## Design goals

1. **Never execute model code.** All analysis is static; pickle streams are
   disassembled, not run.
2. **Fully offline.** No network, no telemetry, no GPU dependency.
3. **Scanners are pure.** Each is a `fn(&Artifact) -> Vec<Finding>` with no shared
   state, which makes them independently testable, safely parallelizable, and the
   plugin seam.
4. **Honest severity.** Every finding carries a confidence and redacted evidence.

## Data flow

```
file ─▶ Artifact::load
          ├─ mmap (zero-copy, handles multi-GB files)
          ├─ format::detect (magic bytes + extension + structure)
          └─ structural parse per format:
               GGUF          → header + metadata KV + tensor descriptors
               safetensors   → u64 header len + JSON __metadata__ + tensors
               PyTorch ZIP   → enumerate pickle streams
               legacy pickle → whole file is one stream
               ONNX          → protobuf: producer, metadata, graph operators
               TensorFlow    → protobuf: harvested operators + strings
               npz (MLX)     → per-array dtype/shape; object arrays → pickle
               hf-config     → JSON parse; string leaves → metadata; auto_map etc.
               csv/tsv/jsonl → bounded sample → schema (columns+types) + rows
       ▼
   scanners run in parallel (rayon), each a read-only fn(&Artifact) -> Vec<Finding>
     built-ins: pickle secrets pii metadata config dataset entropy weights lineage
     rules:     the MODEL_RULE engine (bundled pack + optional --rules dir)
     optional:  experimental detectors (behind --experimental)
       ▼
   Baseline::apply (optional) suppresses accepted fingerprints
       ▼
   Report::new  → sort by severity×confidence
                → aggregate 0–100 risk score (diminishing returns)
                → render human / JSON / SARIF / HTML
```

The `Artifact` struct is the single shared, read-only view every scanner sees:

```rust
pub struct Artifact {
    pub path: PathBuf,
    pub format: ModelFormat,
    pub size: u64,
    map: Mmap,                       // raw bytes, zero-copy
    pub metadata: Vec<(String,String)>,
    pub pickles: Vec<PickleStream>,  // name + bytes
    pub tensor_count: Option<u64>,
    pub tensors: Vec<TensorDesc>,    // name, dtype, shape, exact byte range
    pub graph_ops: Vec<String>,      // ONNX / TF operator kinds
    pub config: Option<Value>,       // parsed JSON for hf-config artifacts
    pub dataset: Option<DatasetInfo>,// schema + sampled rows for csv/tsv/jsonl
}
```

Parsers that consume untrusted, schema-less input (the ONNX/TF protobuf reader
in `pb.rs`) are bounds-checked, depth-bounded, and budget-bounded so a hostile
message cannot cause unbounded recursion, allocation, or out-of-bounds reads.

## Threat model

**Assets:** the machine that loads the model; the credentials/PII embedded in the
artifact; the integrity of downstream inference.

**Adversary:** whoever produced or last modified the artifact (a compromised model
hub account, a malicious fine-tuner, an insider).

**Threats TensorHawk addresses**

| # | Threat | Vector | Scanner |
| --- | --- | --- | --- |
| T1 | Code execution on load | `REDUCE` over `os`/`subprocess`/`ctypes` in pickle | `pickle` |
| T2 | Evasion of pickle scanners | truncated/opcode-fuzzed pickle | `pickle` |
| T3 | Credential leak | keys/tokens in metadata or blobs | `secrets` |
| T4 | PII / privacy leak | personal data in metadata | `pii` |
| T5 | Infra fingerprinting | build paths, internal URLs, cloud IDs | `metadata` |
| T6 | Hidden second-stage payload | packed/encrypted blob in object graph | `entropy` |
| T7 | Code execution via graph op | TF `PyFunc` / custom operators | `rules` (`operators`) |
| T8 | Tampered / poisoned weights | shape·dtype·size mismatch, NaN/Inf, zeroed | `weights` |
| T9 | Unclear chain of custody | LoRA delta, quant/convert ancestry | `lineage` |
| T10 | Code execution via config | `auto_map` / `trust_remote_code` custom Python run on load | `config` |
| T11 | Dataset PII / poisoning | personal data, injection phrases, hidden Unicode in a corpus | `dataset` |

**Explicit non-goals (v0.1):** behavioral/runtime analysis, proving a model is
backdoor-free, or proving training-data provenance. Those are research problems and
will be shipped only behind an `--experimental` flag with clear confidence caveats.

**TensorHawk's own trust boundary:** it parses hostile input, so the parser is the
attack surface. Mitigations: length-capped header fields, bounds-checked cursors,
a bounded pickle shadow-stack, `panic = "abort"`, and fuzz targets on the roadmap.

## The `MODEL_RULE` language (v0.2, shipped)

A YARA-inspired, declarative rule format so detections ship as data, not code.
The runtime loader (lexer + recursive-descent / Pratt parser) lives in
`crates/tensorhawk-core/src/rules`; a bundled reference pack
(`rules/builtin.model_rule`) is embedded in the binary and evaluated on every
scan, and `--rules <dir>` layers in user packs. Targets are `metadata`, `raw`,
`pickle`, and `operators`; condition terms are `$var`, `import("module.name")`,
`opcode(REDUCE)`, and `op("OpType")` combined with `and`/`or`/`not`. The
authoring guide is [`RULES.md`](RULES.md). Sketch:

```
MODEL_RULE aws_key {
    meta:
        id        = "THK-SEC-001"
        severity  = critical
        reference = "OWASP-LLM06, CWE-798"
    target:
        metadata, raw
    strings:
        $k = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/
    condition:
        $k
}

MODEL_RULE pickle_rce {
    meta:
        id       = "THK-PKL-001"
        severity = critical
    target:
        pickle
    condition:
        import("os.system") or import("subprocess.*") and opcode(REDUCE)
}
```

Grammar (EBNF, abbreviated):

```
rule        = "MODEL_RULE" ident "{" meta target (strings)? condition "}" ;
meta        = "meta:" (ident "=" literal)+ ;
target      = "target:" ident ("," ident)* ;
strings     = "strings:" (var "=" (regex | string))+ ;
condition   = "condition:" expr ;
expr        = term (("and"|"or") term)* ;
term        = var | "import" "(" string ")" | "opcode" "(" ident ")"
            | "op" "(" string ")" | "(" expr ")" | "not" term ;
```

The parser is a hand-written recursive-descent tokenizer + Pratt expression parser;
rules compile to the same `Finding` output the built-in scanners already produce.

## Performance plan

- **Now:** mmap for zero-copy over large files; `regex::bytes` directly on the map;
  metadata parsing bounded so hostile headers can't allocate unbounded memory.
- **v0.2:** run scanners concurrently (rayon) and files in parallel.
- **v0.4:** streaming/windowed reads so >100 GB artifacts never fully materialize;
  SIMD-accelerated entropy and multi-pattern matching (AVX2/AVX-512, aho-corasick).
