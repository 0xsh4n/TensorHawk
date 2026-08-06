# Writing `MODEL_RULE` packs

TensorHawk ships detections as **data**. The `MODEL_RULE` engine parses a rule
pack, compiles it into the same `Finding` output the built-in scanners produce,
and evaluates every rule as a pure function of the artifact — no code, no
recompile. This guide is everything you need to write your own pack.

- **Bundled pack:** [`rules/builtin.model_rule`](../rules/builtin.model_rule) is
  embedded in the binary and runs on every scan.
- **Your packs:** point `--rules <dir>` at a directory of `*.model_rule` (or
  `*.rule`) files. They are loaded in sorted filename order and merged with the
  built-ins.

```bash
tensorhawk model.onnx --rules ./my-rules
```

## Anatomy of a rule

```
MODEL_RULE huggingface_token {
    meta:
        id          = "THK-SEC-020"
        title       = "Hugging Face access token"
        severity    = high
        confidence  = 0.85
        reference   = "OWASP-LLM06: Sensitive Information Disclosure"
        reference   = "CWE-798: Use of Hard-coded Credentials"
        remediation = "Rotate the token and rebuild the artifact without it."
    target:
        metadata, raw
    strings:
        $t = /\bhf_[A-Za-z0-9]{34,40}\b/
    condition:
        $t
}
```

A file may contain any number of rules. `#` starts a line comment.

### `meta:` — finding attributes

| Key | Required | Meaning |
| --- | --- | --- |
| `id` | recommended | Stable rule id, e.g. `THK-SEC-020`. Defaults to the rule name. |
| `title` | optional | Human title for the finding. |
| `severity` | optional | `info` \| `low` \| `medium` \| `high` \| `critical` (default `medium`). |
| `confidence` | optional | `0.0`–`1.0` (default `0.8`). |
| `reference` | optional, repeatable | Framework cross-reference (OWASP LLM / MITRE ATLAS / CWE). |
| `remediation` | optional | One-line fix guidance. |

### `target:` — where to look

One or more of:

| Target | Surface |
| --- | --- |
| `metadata` | Container metadata key/value strings. |
| `raw` | The raw mapped bytes of the whole artifact (capped at 256 MiB). |
| `pickle` | Imports and opcodes of embedded pickle streams. |
| `operators` | ONNX / TensorFlow graph operator names. |

### `strings:` — named patterns

Each entry binds a `$name` to a pattern:

```
strings:
    $a = /regex, used verbatim/      # regex literal (slash-delimited)
    $b = "literal text"              # matched literally (auto-escaped)
```

Regex syntax is Rust's [`regex`](https://docs.rs/regex) crate. Escape a literal
slash inside a regex as `\/`.

### `condition:` — the boolean expression

| Term | True when |
| --- | --- |
| `$name` | The named string matches in any targeted surface. |
| `import("module.name")` | A pickle imports a matching global (prefix/`.` semantics like the built-in `pickle` scanner: `os.` matches `os.system`, `os.remove`, …). |
| `opcode(REDUCE)` | The pickle stream contains a REDUCE/build opcode. |
| `op("OpType")` | A graph operator matches. A trailing `*` is a prefix wildcard: `op("PyFunc*")`, `op("com.microsoft.*")`. |
| `not term` | Negation. |
| `a and b`, `a or b` | Boolean composition (`and` binds tighter than `or`; use `(...)` to group). |

## How matches become findings

- A **single-atom** condition (`$x`, `import(...)`, or `op(...)`) emits **one
  finding per concrete match**, so operator and string rules give you precise,
  per-hit locations and evidence.
- Any **composite** condition emits **one finding** when the whole expression
  holds, located at `condition`.
- Identical `(rule_id, evidence)` findings are de-duplicated automatically (e.g.
  a token that appears in both `metadata` and `raw`).

## Redaction & safety

Evidence from `metadata`, `raw`, and `pickle` string matches is **redacted**
before it reaches a report — a rule pack can never exfiltrate a full secret.
Operator evidence (`op(...)`) is shown verbatim, since operator names are not
sensitive.

The parser consumes untrusted rule text: a malformed pack returns an error
(surfaced by `--rules`), never a panic.

## Examples

Dangerous TensorFlow operator (arbitrary Python at inference):

```
MODEL_RULE tf_pyfunc {
    meta: id = "THK-OPS-001" title = "TensorFlow PyFunc runs arbitrary Python"
          severity = critical confidence = 0.9
    target: operators
    condition: op("PyFunc*") or op("EagerPyFunc")
}
```

Pickle code-execution gadget (mirrors the compiled `pickle` scanner):

```
MODEL_RULE pickle_rce {
    meta: id = "THK-PKL-001" severity = critical
    target: pickle
    condition: import("os.system") or (import("subprocess.") and opcode(REDUCE))
}
```

Custom-domain ONNX operator worth review:

```
MODEL_RULE onnx_custom_operator {
    meta: id = "THK-OPS-003" title = "Custom-domain ONNX operator"
          severity = low confidence = 0.5
    target: operators
    strings: $c = /^(?:com\.microsoft|ai\.onnx\.contrib)\./
    condition: $c
}
```

## Grammar (EBNF)

```
ruleset   = rule* ;
rule      = "MODEL_RULE" ident "{" meta target strings? condition "}" ;
meta      = "meta:" (ident "=" literal)+ ;
target    = "target:" ident ("," ident)* ;
strings   = "strings:" (var "=" (regex | string))+ ;
condition = "condition:" expr ;
expr      = term (("and" | "or") term)* ;
term      = var | "import" "(" string ")" | "opcode" "(" ident ")"
          | "op" "(" string ")" | "(" expr ")" | "not" term ;
```

The implementation is a hand-written lexer plus a recursive-descent / Pratt
parser in [`crates/tensorhawk-core/src/rules`](../crates/tensorhawk-core/src/rules).
