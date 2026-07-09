# Security Policy

## Reporting a vulnerability

TensorHawk parses untrusted, potentially hostile files. If you find a way to make
it crash, hang, exhaust memory, or execute code while scanning an artifact, please
report it privately.

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on this repo, or
- Email **security@your-org.example** with steps to reproduce and a sample artifact.

Please do not open a public issue for undisclosed vulnerabilities. We aim to
acknowledge reports within 3 business days.

## Scope

In scope: parser panics/overflows, resource-exhaustion via crafted headers, path
traversal, or any code execution triggered by *scanning* (TensorHawk must never
execute model code).

Out of scope: the model artifacts themselves being malicious — detecting those is
the tool's job, not a vulnerability in the tool.

## Hardening notes

- Scanners never execute model code; pickle streams are statically disassembled.
- Container headers are bounds-checked and length-capped against hostile inputs.
- The release binary is built with `panic = "abort"` and no network access.
