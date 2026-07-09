//! Pickle deserialization scanner.
//!
//! PyTorch `.bin`/`.pt`/`.ckpt` checkpoints are ZIP archives whose object graph
//! is stored as Python pickle. `pickle.load` will execute arbitrary code during
//! deserialization via the `REDUCE` opcode acting on a callable imported by
//! `GLOBAL` / `STACK_GLOBAL`. This is the single most exploited path for model
//! supply-chain attacks (a weights file that runs `os.system(...)` on load).
//!
//! This scanner statically disassembles the opcode stream — it never executes
//! it — resolves every imported `module.name`, and flags callables that can be
//! abused for code execution, network egress, or file access.

use crate::artifact::Artifact;
use crate::finding::{Finding, Location, Severity};
use crate::scanners::Scanner;

pub struct PickleScanner;

impl Scanner for PickleScanner {
    fn id(&self) -> &'static str {
        "pickle"
    }
    fn description(&self) -> &'static str {
        "Detects dangerous imports and opcodes in embedded pickle streams"
    }
    fn scan(&self, artifact: &Artifact) -> Vec<Finding> {
        let mut findings = Vec::new();
        for stream in &artifact.pickles {
            findings.extend(scan_stream(&stream.name, &stream.bytes));
        }
        findings
    }
}

/// `(module, name)` pairs whose import during unpickling is dangerous.
/// Matched by exact `module.name` or by module prefix (trailing `.`).
const DANGEROUS: &[(&str, Severity, &str)] = &[
    ("os.", Severity::Critical, "process/OS control"),
    ("posix.", Severity::Critical, "process/OS control"),
    ("nt.", Severity::Critical, "process/OS control"),
    ("subprocess.", Severity::Critical, "process execution"),
    ("sys.", Severity::High, "interpreter control"),
    ("builtins.eval", Severity::Critical, "arbitrary code eval"),
    ("builtins.exec", Severity::Critical, "arbitrary code exec"),
    ("builtins.compile", Severity::High, "code compilation"),
    ("builtins.__import__", Severity::High, "dynamic import"),
    ("builtins.getattr", Severity::Medium, "attribute pivot"),
    ("builtins.open", Severity::High, "file access"),
    ("__builtin__.eval", Severity::Critical, "arbitrary code eval"),
    ("__builtin__.exec", Severity::Critical, "arbitrary code exec"),
    ("socket.", Severity::High, "network egress"),
    ("shutil.", Severity::High, "filesystem manipulation"),
    ("pty.", Severity::Critical, "interactive shell"),
    ("runpy.", Severity::High, "module execution"),
    ("importlib.", Severity::High, "dynamic import"),
    ("ctypes.", Severity::Critical, "native code / syscalls"),
    ("operator.attrgetter", Severity::Medium, "attribute pivot"),
    ("webbrowser.", Severity::Medium, "process launch"),
    ("urllib.", Severity::High, "network egress"),
    ("requests.", Severity::High, "network egress"),
    ("http.", Severity::Medium, "network egress"),
    ("base64.", Severity::Low, "payload decoding"),
    ("codecs.", Severity::Low, "payload decoding"),
    ("pickle.", Severity::Medium, "nested unpickling"),
    ("bdb.", Severity::Medium, "debugger hook"),
];

/// Imports we consider expected/benign in genuine PyTorch checkpoints.
fn is_benign(module: &str, _name: &str) -> bool {
    module == "torch"
        || module.starts_with("torch.")
        || module.starts_with("numpy")
        || module == "collections"
        || module == "__builtin__" // only benign names reach here
        || module == "builtins"
}

fn classify(module: &str, name: &str) -> Option<(Severity, &'static str)> {
    let full = format!("{module}.{name}");
    for (pat, sev, why) in DANGEROUS {
        let hit = if pat.ends_with('.') {
            module == &pat[..pat.len() - 1] || module.starts_with(pat)
        } else {
            full == *pat
        };
        if hit {
            return Some((*sev, why));
        }
    }
    None
}

fn scan_stream(component: &str, bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let disasm = disassemble(bytes);

    if disasm.truncated {
        findings.push(
            Finding::builder("THK-PKL-090", "pickle", Severity::Medium)
                .title("Unparseable / truncated pickle stream")
                .detail(format!(
                    "The pickle stream in {component} could not be fully disassembled \
                     (unknown opcode at offset {}). Malformed pickles are sometimes used \
                     to evade static scanners.",
                    disasm.stop_offset
                ))
                .location(Location::at(component, disasm.stop_offset as u64))
                .confidence(0.5)
                .reference("OWASP-LLM05: Improper Output/Supply-Chain Handling")
                .build(),
        );
    }

    for imp in &disasm.imports {
        if let Some((sev, why)) = classify(&imp.module, &imp.name) {
            findings.push(
                Finding::builder("THK-PKL-001", "pickle", sev)
                    .title(format!("Dangerous pickle import: {}.{}", imp.module, imp.name))
                    .detail(format!(
                        "The pickle stream imports `{}.{}` ({why}). During `torch.load` / \
                         `pickle.load` this callable can be triggered by a REDUCE opcode to \
                         execute code while the model is being deserialized.",
                        imp.module, imp.name
                    ))
                    .location(Location::at(component, imp.offset as u64))
                    .confidence(if disasm.has_reduce { 0.97 } else { 0.85 })
                    .reference("MITRE-ATLAS: AML.T0010 ML Supply Chain Compromise")
                    .reference("CWE-502: Deserialization of Untrusted Data")
                    .reference("OWASP-LLM05: Supply Chain Vulnerabilities")
                    .remediation(
                        "Do not load this checkpoint with pickle. Prefer safetensors, or \
                         load with `weights_only=True` and verify provenance."
                            .to_string(),
                    )
                    .evidence(format!("GLOBAL {}.{}", imp.module, imp.name))
                    .build(),
            );
        } else if !is_benign(&imp.module, &imp.name) {
            findings.push(
                Finding::builder("THK-PKL-002", "pickle", Severity::Low)
                    .title(format!("Unexpected pickle import: {}.{}", imp.module, imp.name))
                    .detail(format!(
                        "The pickle stream imports `{}.{}`, which is outside the set of \
                         imports expected in a benign PyTorch checkpoint. Review manually.",
                        imp.module, imp.name
                    ))
                    .location(Location::at(component, imp.offset as u64))
                    .confidence(0.4)
                    .build(),
            );
        }
    }

    findings
}

struct Import {
    module: String,
    name: String,
    offset: usize,
}

struct Disasm {
    imports: Vec<Import>,
    has_reduce: bool,
    truncated: bool,
    stop_offset: usize,
}

/// Walk the opcode stream, correctly consuming each opcode's inline arguments so
/// we stay byte-aligned, and record every GLOBAL / STACK_GLOBAL import.
///
/// For STACK_GLOBAL the (module, name) come from two previously pushed strings;
/// we keep a small shadow stack of recently pushed text values to resolve them.
fn disassemble(b: &[u8]) -> Disasm {
    let mut imports = Vec::new();
    let mut str_stack: Vec<String> = Vec::new();
    let mut has_reduce = false;
    let mut i = 0usize;
    let n = b.len();

    macro_rules! need {
        ($k:expr) => {{
            if i + $k > n {
                return Disasm { imports, has_reduce, truncated: true, stop_offset: i };
            }
        }};
    }

    // Read a newline-terminated argument (protocol 0 style). Returns the slice.
    let readline = |b: &[u8], start: usize| -> Option<(String, usize)> {
        let mut j = start;
        while j < b.len() && b[j] != b'\n' {
            j += 1;
        }
        if j >= b.len() {
            return None;
        }
        Some((String::from_utf8_lossy(&b[start..j]).into_owned(), j + 1))
    };

    while i < n {
        let op = b[i];
        let op_off = i;
        i += 1;
        match op {
            // ---- imports --------------------------------------------------
            b'c' => {
                // GLOBAL: module\n name\n
                let (module, ni) = match readline(b, i) {
                    Some(v) => v,
                    None => return Disasm { imports, has_reduce, truncated: true, stop_offset: op_off },
                };
                let (name, ni2) = match readline(b, ni) {
                    Some(v) => v,
                    None => return Disasm { imports, has_reduce, truncated: true, stop_offset: op_off },
                };
                imports.push(Import { module, name, offset: op_off });
                i = ni2;
            }
            b'i' => {
                // INST: module\n name\n
                let (module, ni) = match readline(b, i) {
                    Some(v) => v,
                    None => return Disasm { imports, has_reduce, truncated: true, stop_offset: op_off },
                };
                let (name, ni2) = match readline(b, ni) {
                    Some(v) => v,
                    None => return Disasm { imports, has_reduce, truncated: true, stop_offset: op_off },
                };
                imports.push(Import { module, name, offset: op_off });
                i = ni2;
            }
            0x93 => {
                // STACK_GLOBAL: pop name, module from the shadow stack
                let name = str_stack.pop().unwrap_or_default();
                let module = str_stack.pop().unwrap_or_default();
                imports.push(Import { module, name, offset: op_off });
            }
            b'R' | 0x92 => {
                // REDUCE / NEWOBJ_EX-adjacent construction
                has_reduce = true;
            }
            0x81 => { /* NEWOBJ */ }

            // ---- string pushes (feed the shadow stack) --------------------
            0x8c => {
                // SHORT_BINUNICODE: 1-byte len + utf8
                need!(1);
                let len = b[i] as usize;
                i += 1;
                need!(len);
                str_stack.push(String::from_utf8_lossy(&b[i..i + len]).into_owned());
                i += len;
            }
            b'X' => {
                // BINUNICODE: 4-byte len + utf8
                need!(4);
                let len = u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
                i += 4;
                need!(len);
                str_stack.push(String::from_utf8_lossy(&b[i..i + len]).into_owned());
                i += len;
            }
            0x8d => {
                // BINUNICODE8: 8-byte len + utf8
                need!(8);
                let len = u64::from_le_bytes(b[i..i + 8].try_into().unwrap()) as usize;
                i += 8;
                need!(len);
                str_stack.push(String::from_utf8_lossy(&b[i..i + len]).into_owned());
                i += len;
            }
            b'U' => {
                // SHORT_BINSTRING: 1-byte len + bytes
                need!(1);
                let len = b[i] as usize;
                i += 1;
                need!(len);
                str_stack.push(String::from_utf8_lossy(&b[i..i + len]).into_owned());
                i += len;
            }
            b'T' => {
                // BINSTRING: 4-byte len + bytes
                need!(4);
                let len = u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
                i += 4;
                need!(len);
                str_stack.push(String::from_utf8_lossy(&b[i..i + len]).into_owned());
                i += len;
            }
            b'S' | b'V' | b'p' | b'g' | b'P' => {
                // STRING / UNICODE / PUT / GET / PERSID: newline-terminated
                match readline(b, i) {
                    Some((s, ni)) => {
                        if op == b'S' || op == b'V' {
                            str_stack.push(s);
                        }
                        i = ni;
                    }
                    None => return Disasm { imports, has_reduce, truncated: true, stop_offset: op_off },
                }
            }
            b'F' | b'I' | b'L' => {
                // FLOAT / INT / LONG: newline-terminated numeric
                match readline(b, i) {
                    Some((_, ni)) => i = ni,
                    None => return Disasm { imports, has_reduce, truncated: true, stop_offset: op_off },
                }
            }

            // ---- length-prefixed binary blobs (skip payload) --------------
            b'B' => {
                // BINBYTES: 4-byte len
                need!(4);
                let len = u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
                i += 4;
                need!(len);
                i += len;
            }
            b'C' => {
                // SHORT_BINBYTES: 1-byte len
                need!(1);
                let len = b[i] as usize;
                i += 1;
                need!(len);
                i += len;
            }
            0x8e | 0x96 => {
                // BINBYTES8 / BYTEARRAY8: 8-byte len
                need!(8);
                let len = u64::from_le_bytes(b[i..i + 8].try_into().unwrap()) as usize;
                i += 8;
                need!(len);
                i += len;
            }
            0x8a => {
                // LONG1: 1-byte len + data
                need!(1);
                let len = b[i] as usize;
                i += 1;
                need!(len);
                i += len;
            }
            0x8b => {
                // LONG4: 4-byte len + data
                need!(4);
                let len = u32::from_le_bytes(b[i..i + 4].try_into().unwrap()) as usize;
                i += 4;
                need!(len);
                i += len;
            }

            // ---- fixed-size args -----------------------------------------
            0x80 => { need!(1); i += 1; } // PROTO
            0x95 => { need!(8); i += 1 + 7; } // FRAME: 8-byte length
            b'J' | b'r' | b'j' => { need!(4); i += 4; } // BININT / LONG_BINPUT / LONG_BINGET
            b'K' | b'q' | b'h' => { need!(1); i += 1; } // BININT1 / BINPUT / BINGET
            b'M' => { need!(2); i += 2; } // BININT2
            b'G' => { need!(8); i += 8; } // BINFLOAT
            0x82 => { need!(1); i += 1; } // EXT1
            0x83 => { need!(2); i += 2; } // EXT2
            0x84 => { need!(4); i += 4; } // EXT4

            // ---- zero-arg opcodes ----------------------------------------
            b'(' | b'.' | b'0' | b'1' | b'2' | b'N' | b't' | b'l' | b'd' | b'}' | b']'
            | b')' | b'a' | b'e' | b's' | b'u' | b'b' | b'o' | b'Q' | 0x85 | 0x86 | 0x87
            | 0x88 | 0x89 | 0x8f | 0x90 | 0x91 | 0x94 | 0x97 | 0x98 => {}

            // Unknown opcode: stop and flag as truncated/evasive.
            _ => {
                return Disasm { imports, has_reduce, truncated: true, stop_offset: op_off };
            }
        }

        // Bound the shadow stack so pathological inputs can't blow memory.
        if str_stack.len() > 4096 {
            str_stack.drain(0..2048);
        }
    }

    Disasm { imports, has_reduce, truncated: false, stop_offset: i }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_stack_global_os_system() {
        // Protocol 4 pickle equivalent to: os.system("id")
        // \x80\x04  PROTO 4
        // \x8c\x02os        SHORT_BINUNICODE "os"
        // \x8c\x06system     SHORT_BINUNICODE "system"
        // \x93               STACK_GLOBAL
        // \x8c\x02id         SHORT_BINUNICODE "id"
        // \x85 R .           TUPLE1 REDUCE STOP
        let mut b = vec![0x80, 0x04];
        b.extend_from_slice(&[0x8c, 0x02, b'o', b's']);
        b.extend_from_slice(&[0x8c, 0x06, b's', b'y', b's', b't', b'e', b'm']);
        b.push(0x93);
        b.extend_from_slice(&[0x8c, 0x02, b'i', b'd']);
        b.extend_from_slice(&[0x85, b'R', b'.']);

        let d = disassemble(&b);
        assert!(d.has_reduce);
        assert!(d.imports.iter().any(|i| i.module == "os" && i.name == "system"));
        let findings = scan_stream("archive:data.pkl", &b);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detects_protocol0_global() {
        // cos\nsystem\n(S'id'\ntR.
        let b = b"cos\nsystem\n(S'id'\ntR.";
        let findings = scan_stream("archive:data.pkl", b);
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn benign_torch_import_is_not_critical() {
        // ctorch\nFloatStorage\n
        let b = b"\x80\x04ctorch\nFloatStorage\nq\x00.";
        let findings = scan_stream("archive:data.pkl", b);
        assert!(findings.iter().all(|f| f.severity < Severity::High));
    }
}
