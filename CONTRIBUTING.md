# Contributing to TensorHawk

Thanks for helping make model artifacts safer to load. New **scanners** and
**detection rules** are the highest-value contributions.

## Development setup

```bash
git clone https://github.com/your-org/tensorhawk
cd tensorhawk
cargo build
cargo test
cargo run -p tensorhawk-cli -- tests/fixtures/malicious_model.bin
```

Before opening a PR:

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

## Adding a scanner

A scanner is a pure function of an `Artifact` that returns `Vec<Finding>`. That's
the whole contract — no shared state, no I/O, no network.

1. Create `crates/tensorhawk-core/src/scanners/my_scanner.rs`:

   ```rust
   use crate::artifact::Artifact;
   use crate::finding::{Finding, Location, Severity};
   use crate::scanners::Scanner;

   pub struct MyScanner;

   impl Scanner for MyScanner {
       fn id(&self) -> &'static str { "my_scanner" }
       fn description(&self) -> &'static str { "What it detects, in one line" }
       fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
           let mut findings = Vec::new();
           // inspect artifact.metadata / artifact.pickles / artifact.data()
           findings
       }
   }
   ```

2. Register it in `scanners/mod.rs` (`pub mod my_scanner;` and add it to
   `builtin_scanners()`).

3. Add a fixture under `tests/fixtures/` and a `#[cfg(test)]` unit test that
   proves both a true positive and that a benign input stays clean.

### Finding quality bar

- Every finding needs a **stable `rule_id`** (`THK-<AREA>-NNN`), a **severity**, and a
  **confidence** in `0.0..=1.0`.
- Map to a risk framework where you can: OWASP LLM Top 10, MITRE ATLAS, or CWE.
- **Never emit a secret in full.** Use `finding::redact()` for any credential-like
  evidence.
- Prefer precision. A noisy scanner gets muted; a precise one gets trusted.

## Reporting security issues

Do not open a public issue for a vulnerability in TensorHawk itself. See
[`SECURITY.md`](SECURITY.md).

## License of contributions

By contributing you agree your contributions are licensed under Apache-2.0.
