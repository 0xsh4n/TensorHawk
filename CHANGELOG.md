# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/0xsh4n/TensorHawk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/0xsh4n/TensorHawk/releases/tag/v0.1.0
