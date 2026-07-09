# Developer Guide

Everything you need to build, run, test, and hack on TensorHawk from a **fresh
Linux VM**. Follow it top to bottom the first time; later you'll only need the
[Daily workflow](#daily-workflow) section.

> TL;DR for the impatient:
> ```bash
> sudo apt-get update && sudo apt-get install -y build-essential pkg-config git
> curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
> source "$HOME/.cargo/env"
> tar xzf tensorhawk.tar.gz && cd tensorhawk
> cargo build --release
> ./target/release/tensorhawk tests/fixtures/malicious_model.bin
> ```

---

## 1. System requirements

| Requirement | Version | Why |
| --- | --- | --- |
| OS | Any 64-bit Linux (Ubuntu 20.04+/Debian 11+ tested) | — |
| Rust | **1.75.0 or newer** (MSRV is 1.75) | Edition 2021, workspace |
| C toolchain | `gcc` + `pkg-config` | The linker; some crates build tiny C shims |
| git | any | Cloning, tagging releases |
| RAM | ~2 GB to compile | LTO release build is the heaviest step |
| Disk | ~2 GB | `target/` grows with build artifacts |

TensorHawk has **no runtime system dependencies** — no OpenSSL, no zlib, no
Python, no GPU. Compression (`zip`/`flate2`) and hashing are pure-Rust, so the
release binary is a single static-ish executable you can copy anywhere with the
same libc.

---

## 2. Install the toolchain on a clean VM

### 2a. System packages

Debian / Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config git curl
```

Fedora / RHEL:

```bash
sudo dnf install -y gcc pkg-config git curl
```

### 2b. Rust via rustup (recommended)

`rustup` gives you a per-user toolchain (no root needed after this) and the
`rustfmt`/`clippy` components CI expects.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"          # add this to ~/.bashrc for future shells
rustup component add rustfmt clippy
```

Verify:

```bash
rustc --version   # rustc 1.75.0 (or newer)
cargo --version
```

> The repo contains a `rust-toolchain.toml` pinning `channel = "stable"` with the
> `rustfmt` and `clippy` components. With rustup installed, cargo will honor it
> automatically — the first `cargo` command inside the repo may download the
> matching toolchain.

<details>
<summary>Alternative: distro Rust without rustup</summary>

You *can* use `sudo apt-get install -y cargo rustc` if your distro ships Rust
1.75+. Two caveats:

- `rustfmt`/`clippy` may be separate packages (`rustfmt`, `clippy` or
  `rust-clippy`); without them the `cargo fmt`/`cargo clippy` steps won't run
  locally (CI still runs them).
- If the distro Rust is **older than 1.75**, the build will fail. Use rustup.

Because a `rust-toolchain.toml` is present, rustup (if also installed) will
override the distro toolchain inside this directory. Pick one approach to avoid
confusion; rustup is the supported path.
</details>

---

## 3. Get the source

If you have the tarball:

```bash
tar xzf tensorhawk.tar.gz
cd tensorhawk
```

Once it's on GitHub:

```bash
git clone https://github.com/your-org/tensorhawk
cd tensorhawk
```

Project layout:

```
tensorhawk/
├── Cargo.toml              # workspace root (resolver=2, release profile)
├── Cargo.lock              # PINNED — commit it, do not regenerate (see §7)
├── rust-toolchain.toml     # channel = stable + rustfmt, clippy
├── crates/
│   ├── tensorhawk-core/    # the engine (library)
│   │   ├── src/
│   │   │   ├── lib.rs          # public API: analyze(), analyze_with()
│   │   │   ├── artifact.rs     # mmap load + GGUF/safetensors/zip parsing
│   │   │   ├── format.rs       # magic-byte format detection
│   │   │   ├── finding.rs      # Severity, Finding, redact()
│   │   │   ├── report.rs       # risk score + JSON/SARIF/human output
│   │   │   └── scanners/       # pickle, secrets, pii, metadata, entropy
│   │   └── tests/integration.rs
│   └── tensorhawk-cli/     # the `tensorhawk` binary (clap CLI)
│       └── src/main.rs
├── rules/                  # declarative rule pack reference (v0.2 engine)
├── tests/fixtures/         # golden malicious/benign artifacts
└── .github/workflows/      # ci.yml + release.yml
```

---

## 4. Build

Debug build (fast compile, unoptimized — use while developing):

```bash
cargo build
# binary at target/debug/tensorhawk
```

Release build (optimized: `lto=thin`, `panic=abort`, stripped — ~2.6 MB binary):

```bash
cargo build --release
# binary at target/release/tensorhawk
```

The first build downloads and compiles all dependencies from crates.io and can
take a few minutes; the release build's LTO step is the slow part (~2 min on a
modest VM). Subsequent builds are incremental and fast.

> **Network note:** the build fetches crates from `crates.io` / `static.crates.io`.
> If your VM is behind a firewall or air-gapped, either allow those hosts or
> `cargo vendor` the dependencies on a connected machine and copy them over.

---

## 5. Run

```bash
# scan a single model
./target/release/tensorhawk model.safetensors

# scan a directory recursively, fail (exit 1) on high+ findings
./target/release/tensorhawk ./models --recursive --fail-on high

# machine-readable output
./target/release/tensorhawk model.bin --format json  > report.json
./target/release/tensorhawk model.bin --format sarif > report.sarif

# show only medium and above, no ANSI colour
./target/release/tensorhawk model.bin --min-severity medium --no-color
```

Try it immediately against the checked-in fixtures:

```bash
./target/release/tensorhawk tests/fixtures/malicious_model.bin   # CRITICAL pickle RCE, exit 1
./target/release/tensorhawk tests/fixtures/leaky.safetensors     # leaked AWS key, exit 1
./target/release/tensorhawk tests/fixtures/model.gguf            # PII (email), exit 0
./target/release/tensorhawk tests/fixtures/benign_model.bin      # clean, exit 0
```

### CLI reference

| Flag | Default | Meaning |
| --- | --- | --- |
| `PATH` (positional) | — | Model file or directory to scan |
| `-f, --format <fmt>` | `human` | `human` \| `json` \| `sarif` |
| `-o, --output <FILE>` | stdout | Write report to a file |
| `-r, --recursive` | off | Recurse into directories |
| `--min-severity <sev>` | `info` | Hide findings below this level |
| `--fail-on <sev>` | `high` | Exit non-zero if any finding ≥ this level |
| `--no-color` | off | Disable ANSI colour in human output |

Severity levels: `info < low < medium < high < critical`.

### Exit codes (useful in CI / scripts)

| Code | Meaning |
| --- | --- |
| `0` | Completed; nothing at/above `--fail-on` |
| `1` | Completed; a finding at/above `--fail-on` was reported |
| `2` | No scannable artifact found at the given path |

---

## 6. Test, format, lint

Run exactly what CI runs before you push:

```bash
cargo fmt --all --check                     # formatting gate
cargo clippy --all-targets -- -D warnings   # lint gate (warnings = errors)
cargo test --all                            # unit + integration + doctests
```

Auto-fix formatting:

```bash
cargo fmt --all
```

The test suite currently has 8 tests: 3 pickle-scanner unit tests, 4 end-to-end
integration tests over the fixtures, and 1 doctest on the public API. A green
`cargo test --all` plus the two gates above means CI will pass.

---

## 7. ⚠️ The `Cargo.lock` pin — read before touching dependencies

This repo commits `Cargo.lock`, and it is **intentionally pinned** to versions
that build on the 1.75 MSRV. A newer transitive `clap_lex` requires the
`edition2024` feature, which Rust 1.75 cannot compile.

**Do:**
- Keep `Cargo.lock` committed.
- Build with `cargo build` (which respects the lockfile).

**Avoid unless you also bump the MSRV:**
- `cargo update` (upgrades transitive deps and can re-break 1.75).
- Deleting `Cargo.lock` and regenerating it on a 1.75 toolchain.

If you *do* want to move to a newer dependency set, raise the MSRV: edit the
`msrv` job in `.github/workflows/ci.yml`, update the README badge, run
`cargo update`, and confirm `cargo +1.<new> build --all` is green. If you're on
a recent stable toolchain and only ever build with that, a fresh `cargo update`
is fine — the pin only matters for the 1.75 floor.

---

## 8. Regenerating the test fixtures (optional)

The fixtures under `tests/fixtures/` are small crafted artifacts. They're
committed, so you don't need Python to build or test. If you want to recreate or
extend them:

```bash
cd tests/fixtures
python3 - <<'PY'
import pickle, zipfile, struct, json, os

# 1) Malicious PyTorch checkpoint: data.pkl runs os.system on load
class Evil:
    def __reduce__(self):
        return (os.system, ("id # pwned",))
with zipfile.ZipFile("malicious_model.bin", "w") as z:
    z.writestr("archive/data.pkl", pickle.dumps(Evil(), protocol=4))

# 2) Benign checkpoint
with zipfile.ZipFile("benign_model.bin", "w") as z:
    z.writestr("archive/data.pkl",
               pickle.dumps({"weight": [0.1, 0.2], "config": {"layers": 12}}, protocol=4))

# 3) safetensors with a leaked AWS key + build path in metadata
header = {"__metadata__": {"format": "pt",
                            "trained_by": "/home/mchen/experiments/run42",
                            "aws_key": "AKIAIOSFODNN7EXAMPLE",
                            "notes": "internal build, see https://mlflow.corp.internal/run/42"},
          "weight": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}}
hb = json.dumps(header).encode()
with open("leaky.safetensors", "wb") as f:
    f.write(struct.pack("<Q", len(hb))); f.write(hb); f.write(b"\x00" * 64)

# 4) minimal GGUF with an author email in metadata
def gstr(s): b = s.encode(); return struct.pack("<Q", len(b)) + b
buf = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", 2)
buf += gstr("general.author") + struct.pack("<I", 8) + gstr("Jane Doe <jane.doe@example.com>")
buf += gstr("general.name")   + struct.pack("<I", 8) + gstr("tiny-llm")
open("model.gguf", "wb").write(buf)
print("fixtures regenerated")
PY
```

After regenerating, `cargo test --all` should still pass — the integration tests
assert on these exact artifacts.

---

## 9. Add a scanner (the common change)

A scanner is a pure `fn(&Artifact) -> Vec<Finding>` implementing one trait. Full
worked example in [`CONTRIBUTING.md`](CONTRIBUTING.md); the short version:

1. Add `crates/tensorhawk-core/src/scanners/my_scanner.rs` implementing `Scanner`.
2. Register it in `scanners/mod.rs` (`pub mod my_scanner;` + add to
   `builtin_scanners()`).
3. Add a fixture and a unit test proving one true positive and one clean case.
4. `cargo test --all && cargo clippy --all-targets -- -D warnings`.

---

## 10. Cutting a release from your VM

Releases are produced by `.github/workflows/release.yml` when you push a
`v*.*.*` tag; GitHub then cross-compiles Linux (gnu + musl), macOS (x86_64 +
arm64), and Windows binaries, generates `SHA256SUMS`, and publishes a GitHub
Release.

```bash
# 1) make sure main is green, bump versions in Cargo.toml + CHANGELOG.md
git commit -am "Release v0.1.0"
git push origin main

# 2) tag and push — this triggers the release workflow
git tag v0.1.0
git push origin v0.1.0
```

To build a release artifact **locally** for your own platform instead:

```bash
cargo build --release
tar czf tensorhawk-$(uname -m)-linux.tar.gz -C target/release tensorhawk
sha256sum tensorhawk-$(uname -m)-linux.tar.gz > SHA256SUMS
```

Cross-compiling locally (e.g. a static musl binary) needs the target and a
linker:

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools
cargo build --release --target x86_64-unknown-linux-musl
```

> Remember to replace the `your-org` placeholder in `Cargo.toml`, the README
> badges, and the workflow URLs with your actual GitHub org/username before you
> push.

---

## 11. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `error: package requires rustc 1.xx` or an `edition2024` error | Toolchain older than 1.75, or `Cargo.lock` was regenerated. Use rustup stable and restore the committed lockfile (see §7). |
| `linker 'cc' not found` | Install `build-essential` (Debian) / `gcc` (Fedora). |
| `no such command: clippy`/`fmt` | `rustup component add clippy rustfmt` (or install the distro `clippy`/`rustfmt` packages). |
| crates.io fetch hangs/fails | VM has no egress to `crates.io`/`static.crates.io`. Allow them or `cargo vendor` offline. |
| `Broken pipe` panic when piping to `head` | Harmless: the reader closed early. Redirect to a file, or ignore. |
| Release build feels stuck | The `lto = "thin"` step is single-threaded and slow (~2 min). It's working; wait it out. |
| Windows-specific behavior | The CLI uses a Unix `isatty` check for colour; on Windows use `--no-color` or rely on the released build. |

---

## 12. Quick command reference

```bash
cargo build                 # debug build
cargo build --release       # optimized binary -> target/release/tensorhawk
cargo run -p tensorhawk-cli -- <path> [flags]   # build + run in one step
cargo test --all            # all tests
cargo fmt --all             # format
cargo clippy --all-targets -- -D warnings       # lint
```
