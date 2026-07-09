//! Loading and light structural parsing of a model artifact.
//!
//! We memory-map the file and, depending on the detected format, extract a
//! common set of structures that scanners operate on:
//! * `metadata`   — key/value strings pulled from the container header
//! * `pickle`     — named pickle byte streams (for PyTorch archives)
//! * `data`       — the raw mapped bytes (for regex/entropy passes)

use crate::format::{self, ModelFormat};
use anyhow::{Context, Result};
use memmap2::Mmap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// A named pickle byte stream extracted from a container.
pub struct PickleStream {
    pub name: String,
    pub bytes: Vec<u8>,
}

pub struct Artifact {
    pub path: PathBuf,
    pub format: ModelFormat,
    pub size: u64,
    map: Mmap,
    pub metadata: Vec<(String, String)>,
    pub pickles: Vec<PickleStream>,
    /// Number of tensors declared by the container header, if known.
    pub tensor_count: Option<u64>,
}

impl Artifact {
    /// Raw mapped bytes. Backed by mmap, so this is zero-copy.
    pub fn data(&self) -> &[u8] {
        &self.map
    }

    /// Load and structurally parse an artifact from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        let size = file.metadata()?.len();
        // SAFETY: file is opened read-only; we treat the map as immutable.
        let map = unsafe { Mmap::map(&file)? };

        let prefix = &map[..map.len().min(64)];
        let format = format::detect(path, prefix);

        let mut artifact = Artifact {
            path: path.to_path_buf(),
            format,
            size,
            map,
            metadata: Vec::new(),
            pickles: Vec::new(),
            tensor_count: None,
        };

        match format {
            ModelFormat::Gguf => artifact.parse_gguf(),
            ModelFormat::Safetensors => artifact.parse_safetensors(),
            ModelFormat::PyTorchZip => artifact.parse_pytorch_zip(),
            ModelFormat::PyTorchLegacyPickle => {
                artifact.pickles.push(PickleStream {
                    name: "archive:legacy.pkl".to_string(),
                    bytes: artifact.map.to_vec(),
                });
            }
            _ => {}
        }

        Ok(artifact)
    }

    // ---- GGUF -----------------------------------------------------------

    fn parse_gguf(&mut self) {
        // Header: magic[4] version[u32] tensor_count[u64] kv_count[u64] (v>=2)
        let mut c = Cursor::new(self.map.as_ref());
        if c.take(4).is_none() {
            return;
        }
        let version = match c.u32() {
            Some(v) => v,
            None => return,
        };
        let (tensor_count, kv_count) = if version >= 2 {
            match (c.u64(), c.u64()) {
                (Some(t), Some(k)) => (t, k),
                _ => return,
            }
        } else {
            match (c.u32(), c.u32()) {
                (Some(t), Some(k)) => (t as u64, k as u64),
                _ => return,
            }
        };
        self.tensor_count = Some(tensor_count);

        // Guard against corrupt/hostile headers claiming millions of keys.
        let kv_count = kv_count.min(100_000);
        for _ in 0..kv_count {
            let key = match c.gguf_string() {
                Some(k) => k,
                None => break,
            };
            match c.gguf_value_as_string() {
                Some(val) if !val.is_empty() => self.metadata.push((key, val)),
                Some(_) => {}
                None => break,
            }
        }
    }

    // ---- safetensors ----------------------------------------------------

    fn parse_safetensors(&mut self) {
        if self.map.len() < 8 {
            return;
        }
        let hdr_len = u64::from_le_bytes(self.map[0..8].try_into().unwrap()) as usize;
        let end = 8usize.saturating_add(hdr_len);
        if end > self.map.len() {
            return;
        }
        let header = &self.map[8..end];
        let json: serde_json::Value = match serde_json::from_slice(header) {
            Ok(v) => v,
            Err(_) => return,
        };
        if let Some(obj) = json.as_object() {
            self.tensor_count = Some(obj.keys().filter(|k| *k != "__metadata__").count() as u64);
            if let Some(meta) = obj.get("__metadata__").and_then(|m| m.as_object()) {
                for (k, v) in meta {
                    if let Some(s) = v.as_str() {
                        self.metadata.push((k.clone(), s.to_string()));
                    }
                }
            }
        }
    }

    // ---- PyTorch ZIP ----------------------------------------------------

    fn parse_pytorch_zip(&mut self) {
        let cursor = std::io::Cursor::new(self.map.as_ref());
        let mut zip = match zip::ZipArchive::new(cursor) {
            Ok(z) => z,
            Err(_) => return,
        };
        for i in 0..zip.len() {
            let mut entry = match zip.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            };
            let name = entry.name().to_string();
            let is_pkl = name.ends_with(".pkl") || name.ends_with("data.pkl");
            // Read a small prefix cheaply to sniff bare pickle streams too.
            let mut buf = Vec::new();
            if entry.read_to_end(&mut buf).is_err() {
                continue;
            }
            if is_pkl || matches!(buf.first(), Some(0x80)) {
                self.pickles.push(PickleStream {
                    name: format!("archive:{name}"),
                    bytes: buf,
                });
            }
        }
    }
}

/// Minimal forward-only byte cursor with the primitives GGUF needs.
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Cursor { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.b.len() {
            return None;
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn gguf_string(&mut self) -> Option<String> {
        let len = self.u64()? as usize;
        if len > 64 * 1024 * 1024 {
            return None; // reject absurd lengths
        }
        let bytes = self.take(len)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
    /// Read a GGUF metadata value, coercing to a printable string where it
    /// carries text; numeric scalars/arrays are skipped (returns empty).
    fn gguf_value_as_string(&mut self) -> Option<String> {
        const STRING: u32 = 8;
        const ARRAY: u32 = 9;
        let vtype = self.u32()?;
        match vtype {
            STRING => self.gguf_string(),
            ARRAY => {
                let elem_type = self.u32()?;
                let count = self.u64()? as usize;
                if count > 1_000_000 {
                    return None;
                }
                if elem_type == STRING {
                    let mut parts = Vec::new();
                    for _ in 0..count {
                        parts.push(self.gguf_string()?);
                    }
                    Some(parts.join(" "))
                } else {
                    let sz = scalar_size(elem_type)?;
                    self.take(sz.checked_mul(count)?)?;
                    Some(String::new())
                }
            }
            other => {
                let sz = scalar_size(other)?;
                self.take(sz)?;
                Some(String::new())
            }
        }
    }
}

fn scalar_size(t: u32) -> Option<usize> {
    Some(match t {
        0 | 1 | 7 => 1,        // uint8 / int8 / bool
        2 | 3 => 2,            // uint16 / int16
        4 | 5 | 6 => 4,        // uint32 / int32 / float32
        10 | 11 | 12 => 8,     // uint64 / int64 / float64
        _ => return None,
    })
}
