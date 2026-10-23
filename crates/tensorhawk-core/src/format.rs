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
    /// TensorFlow SavedModel protobuf (`saved_model.pb`) or frozen `GraphDef`.
    TensorFlow,
    /// MLX / NumPy `.npz` zip of `.npy` arrays.
    Npz,
    /// A Hugging Face / diffusers JSON config (`config.json`, `tokenizer_config.json`,
    /// `adapter_config.json`, `model_index.json`, …). Not weights, but the surface
    /// where custom-code execution (`auto_map` / `trust_remote_code`) is declared.
    HfConfig,
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
            ModelFormat::TensorFlow => "tensorflow",
            ModelFormat::Npz => "npz",
            ModelFormat::HfConfig => "hf-config",
            ModelFormat::Unknown => "unknown",
        }
    }
}

/// True if `prefix` begins with a strong, unambiguous model-container magic:
/// GGUF, GGML, a ZIP local-file header (PyTorch/npz), or a safetensors header
/// (u64 length followed by `{`).
///
/// Used to pick up extensionless model files during directory discovery — most
/// importantly Ollama's `sha256-<hash>` blobs, which carry no extension. It
/// deliberately excludes the weaker pickle/JSON heuristics, which would
/// over-match arbitrary text files when sweeping a directory.
pub fn has_model_magic(prefix: &[u8]) -> bool {
    if prefix.len() >= 4 && (&prefix[0..4] == b"GGUF" || &prefix[0..4] == b"GGML") {
        return true;
    }
    if prefix.len() >= 4 && &prefix[0..4] == b"PK\x03\x04" {
        return true;
    }
    if prefix.len() >= 9 {
        let hdr_len = u64::from_le_bytes(prefix[0..8].try_into().unwrap());
        if hdr_len > 0 && prefix[8] == b'{' {
            return true;
        }
    }
    false
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

/// True if `prefix`, ignoring leading ASCII whitespace, begins with `{` — the
/// start of a JSON object (used to confirm a `.json` file is a config document).
fn starts_with_json_object(prefix: &[u8]) -> bool {
    prefix
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|&b| b == b'{')
}

/// Best-effort format detection using the file prefix and extension.
pub fn detect(path: &std::path::Path, prefix: &[u8]) -> ModelFormat {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let file_name = path
        .file_name()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if prefix.len() >= 4 && &prefix[0..4] == b"GGUF" {
        return ModelFormat::Gguf;
    }
    if prefix.len() >= 4 && &prefix[0..4] == b"GGML" {
        return ModelFormat::Ggml;
    }
    // ZIP local file header. NumPy/MLX `.npz` archives are also ZIPs, so
    // disambiguate on extension; otherwise it is almost always a PyTorch archive.
    if prefix.len() >= 4 && &prefix[0..4] == b"PK\x03\x04" {
        if ext == "npz" {
            return ModelFormat::Npz;
        }
        return ModelFormat::PyTorchZip;
    }
    // ONNX and TensorFlow are both bare protobuf with no reliable magic, so we
    // key off the extension / conventional filename.
    if ext == "onnx" {
        return ModelFormat::Onnx;
    }
    if ext == "pb" || file_name == "saved_model.pb" || file_name == "saved_model.pbtxt" {
        return ModelFormat::TensorFlow;
    }
    if ext == "npz" {
        return ModelFormat::Npz;
    }
    // Hugging Face / diffusers JSON configs. We key off the `.json` extension and
    // confirm the payload begins (ignoring leading whitespace) with a JSON object,
    // so a stray `.json` that is not an object falls through to Unknown.
    if ext == "json" && starts_with_json_object(prefix) {
        return ModelFormat::HfConfig;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_magic_matches_gguf_without_extension() {
        // Ollama stores models as extensionless `sha256-...` blobs; the magic
        // must still identify them.
        assert!(has_model_magic(b"GGUF\x03\x00\x00\x00rest"));
        assert!(has_model_magic(b"GGML....."));
        assert!(has_model_magic(b"PK\x03\x04zip-local-header"));
    }

    #[test]
    fn model_magic_matches_safetensors_header() {
        // 8-byte LE header length (non-zero) followed by '{'.
        let mut b = (2u64).to_le_bytes().to_vec();
        b.push(b'{');
        b.push(b'}');
        assert!(has_model_magic(&b));
    }

    #[test]
    fn model_magic_rejects_arbitrary_text() {
        // The strong-magic check must not over-match random files during a
        // directory sweep (unlike the weaker pickle/JSON heuristics).
        assert!(!has_model_magic(b"#!/usr/bin/env python\n"));
        assert!(!has_model_magic(b"{ \"just\": \"json\" }"));
        assert!(!has_model_magic(b"\x80\x04 pickle-ish"));
        assert!(!has_model_magic(b"short"));
    }
}
