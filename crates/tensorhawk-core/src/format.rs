//! Model container format detection via magic bytes and structure.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFormat {
    /// GGUF (llama.cpp) container.
    Gguf,
    /// Legacy GGML container.
    Ggml,
    /// Hugging Face safetensors.
    Safetensors,
    /// PyTorch `torch.save` ZIP archive (contains pickle streams).
    PyTorchZip,
    /// Legacy raw pickle checkpoint (`.bin`/`.pt` that is a bare pickle).
    PyTorchLegacyPickle,
    /// ONNX protobuf.
    Onnx,
    Unknown,
}

impl ModelFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModelFormat::Gguf => "gguf",
            ModelFormat::Ggml => "ggml",
            ModelFormat::Safetensors => "safetensors",
            ModelFormat::PyTorchZip => "pytorch-zip",
            ModelFormat::PyTorchLegacyPickle => "pytorch-legacy-pickle",
            ModelFormat::Onnx => "onnx",
            ModelFormat::Unknown => "unknown",
        }
    }
}

/// A pickle stream begins with the PROTO opcode (0x80) or one of the
/// classic protocol-0 opcodes.
fn looks_like_pickle(bytes: &[u8]) -> bool {
    match bytes.first() {
        Some(0x80) => true, // PROTO
        // Common protocol-0/1 leading opcodes: '(' MARK, 'c' GLOBAL, '}' EMPTY_DICT
        Some(b'(') | Some(b'c') | Some(b'}') | Some(b']') => bytes.len() > 2,
        _ => false,
    }
}

/// Best-effort format detection using the file prefix and extension.
pub fn detect(path: &std::path::Path, prefix: &[u8]) -> ModelFormat {
    if prefix.len() >= 4 && &prefix[0..4] == b"GGUF" {
        return ModelFormat::Gguf;
    }
    if prefix.len() >= 4 && &prefix[0..4] == b"GGML" {
        return ModelFormat::Ggml;
    }
    // ZIP local file header -> almost always a PyTorch archive for our inputs.
    if prefix.len() >= 4 && &prefix[0..4] == b"PK\x03\x04" {
        return ModelFormat::PyTorchZip;
    }
    // ONNX protobuf files usually start with field 1 (ir_version) tag 0x08.
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "onnx" {
        return ModelFormat::Onnx;
    }

    // Safetensors: first 8 bytes are a little-endian u64 header length, and
    // the bytes that follow are a JSON object starting with '{'.
    if prefix.len() >= 9 {
        let hdr_len = u64::from_le_bytes(prefix[0..8].try_into().unwrap());
        if hdr_len > 0 && prefix[8] == b'{' {
            return ModelFormat::Safetensors;
        }
    }

    if looks_like_pickle(prefix) {
        return ModelFormat::PyTorchLegacyPickle;
    }

    ModelFormat::Unknown
}
