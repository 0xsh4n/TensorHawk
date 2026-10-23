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

/// A tensor described by a container header: its logical name, dtype, shape,
/// and — when the container gives an exact byte layout — its absolute range in
/// the mapped file (so the weight-integrity scanner can inspect it zero-copy).
#[derive(Debug, Clone)]
pub struct TensorDesc {
    pub name: String,
    pub dtype: String,
    pub shape: Vec<u64>,
    /// Absolute `[start, end)` byte range in the mapped file, when known exactly.
    pub data: Option<(u64, u64)>,
}

/// A column (CSV/TSV) or field (JSONL) discovered in a dataset, with a coarse
/// inferred type over the sampled rows.
#[derive(Debug, Clone)]
pub struct DatasetColumn {
    pub name: String,
    /// One of `int`, `float`, `bool`, `string`, `empty` (best-effort).
    pub inferred_type: String,
}

/// Lightweight structural view of a tabular / line-delimited dataset, built from
/// a bounded sample of the file. This is what lets the `dataset` scanner report
/// schema and scan content for PII / poisoning indicators without loading the
/// whole (possibly multi-GB) file.
#[derive(Debug, Clone)]
pub struct DatasetInfo {
    /// `csv`, `tsv`, or `jsonl`.
    pub kind: &'static str,
    pub columns: Vec<DatasetColumn>,
    /// Sampled rows as `(column, value)` pairs; values are length-capped.
    pub rows: Vec<Vec<(String, String)>>,
    /// Number of rows parsed in the sample (excludes the CSV/TSV header).
    pub rows_scanned: usize,
    /// True if the file was larger than the sample window (so counts are a
    /// lower bound and the readout is of a prefix, not the whole file).
    pub truncated: bool,
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
    /// Tensor descriptors parsed from the header (safetensors / GGUF / npz).
    pub tensors: Vec<TensorDesc>,
    /// Graph operator / node kinds harvested from ONNX / TensorFlow graphs.
    pub graph_ops: Vec<String>,
    /// Parsed JSON for config artifacts (Hugging Face `config.json`, etc.), when
    /// the format is [`ModelFormat::HfConfig`]. Lets the `config` scanner inspect
    /// structure (e.g. `auto_map`) without re-parsing.
    pub config: Option<serde_json::Value>,
    /// Structural view of a dataset artifact (CSV/TSV/JSONL), when applicable.
    pub dataset: Option<DatasetInfo>,
}

impl Artifact {
    /// Raw mapped bytes. Backed by mmap, so this is zero-copy.
    pub fn data(&self) -> &[u8] {
        &self.map
    }

    /// The raw bytes backing a tensor, when its exact range is known and in
    /// bounds. Zero-copy slice into the mmap.
    pub fn tensor_bytes(&self, t: &TensorDesc) -> Option<&[u8]> {
        let (start, end) = t.data?;
        let (start, end) = (start as usize, end as usize);
        if start <= end && end <= self.map.len() {
            Some(&self.map[start..end])
        } else {
            None
        }
    }

    /// Load and structurally parse an artifact from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let file =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
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
            tensors: Vec::new(),
            graph_ops: Vec::new(),
            config: None,
            dataset: None,
        };

        match format {
            ModelFormat::Gguf => artifact.parse_gguf(),
            ModelFormat::Safetensors => artifact.parse_safetensors(),
            ModelFormat::PyTorchZip => artifact.parse_pytorch_zip(),
            ModelFormat::Onnx => artifact.parse_onnx(),
            ModelFormat::TensorFlow => artifact.parse_tensorflow(),
            ModelFormat::Npz => artifact.parse_npz(),
            ModelFormat::HfConfig => artifact.parse_hf_config(),
            ModelFormat::Csv => artifact.parse_delimited(b','),
            ModelFormat::Tsv => artifact.parse_delimited(b'\t'),
            ModelFormat::Jsonl => artifact.parse_jsonl(),
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
        let mut kv_ok = true;
        for _ in 0..kv_count {
            let key = match c.gguf_string() {
                Some(k) => k,
                None => {
                    kv_ok = false;
                    break;
                }
            };
            match c.gguf_value_as_string() {
                Some(val) if !val.is_empty() => self.metadata.push((key, val)),
                Some(_) => {}
                None => {
                    kv_ok = false;
                    break;
                }
            }
        }

        // Tensor info section follows the KV block, but only if we parsed it
        // cleanly (otherwise the cursor is at an unknown offset).
        if !kv_ok {
            return;
        }
        let tensor_count = tensor_count.min(1_000_000);
        for _ in 0..tensor_count {
            let name = match c.gguf_string() {
                Some(n) => n,
                None => break,
            };
            let n_dims = match c.u32() {
                Some(d) if d <= 8 => d,
                _ => break,
            };
            let mut shape = Vec::with_capacity(n_dims as usize);
            let mut ok = true;
            for _ in 0..n_dims {
                match c.u64() {
                    Some(d) => shape.push(d),
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                break;
            }
            let dtype = match c.u32() {
                Some(t) => ggml_type_name(t),
                None => break,
            };
            // Offset into the (aligned) data block; we record the descriptor but
            // not an absolute range, since GGUF data-section alignment is not
            // reconstructed here.
            if c.u64().is_none() {
                break;
            }
            self.tensors.push(TensorDesc {
                name,
                dtype: dtype.to_string(),
                shape,
                data: None,
            });
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
            // Tensor descriptors. Offsets in the header are relative to the
            // start of the data block, which begins right after the header.
            let data_start = end as u64;
            for (name, spec) in obj {
                if name == "__metadata__" {
                    continue;
                }
                let spec = match spec.as_object() {
                    Some(s) => s,
                    None => continue,
                };
                let dtype = spec
                    .get("dtype")
                    .and_then(|d| d.as_str())
                    .unwrap_or("?")
                    .to_string();
                let shape = spec
                    .get("shape")
                    .and_then(|s| s.as_array())
                    .map(|a| a.iter().filter_map(|v| v.as_u64()).collect())
                    .unwrap_or_default();
                let data = spec
                    .get("data_offsets")
                    .and_then(|o| o.as_array())
                    .filter(|a| a.len() == 2)
                    .and_then(|a| Some((a[0].as_u64()?, a[1].as_u64()?)))
                    .map(|(b, e)| (data_start + b, data_start + e));
                self.tensors.push(TensorDesc {
                    name: name.clone(),
                    dtype,
                    shape,
                    data,
                });
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

    // ---- ONNX (protobuf) ------------------------------------------------

    fn parse_onnx(&mut self) {
        use crate::pb::{as_string, Field, Reader};
        // ONNX ModelProto: 2=producer_name, 3=producer_version, 6=doc_string,
        // 7=graph (GraphProto), 8=opset_import (OperatorSetIdProto),
        // 14=metadata_props (StringStringEntryProto{1=key,2=value}).
        let mut r = Reader::new(self.map.as_ref());
        while let Some((field, val)) = r.next_field() {
            match (field, val) {
                (2, Field::Len(b)) => {
                    if let Some(s) = as_string(b) {
                        self.metadata.push(("onnx.producer_name".into(), s));
                    }
                }
                (3, Field::Len(b)) => {
                    if let Some(s) = as_string(b) {
                        self.metadata.push(("onnx.producer_version".into(), s));
                    }
                }
                (6, Field::Len(b)) => {
                    if let Some(s) = as_string(b) {
                        self.metadata.push(("onnx.doc_string".into(), s));
                    }
                }
                (7, Field::Len(b)) => {
                    let (ops, tensors) = parse_onnx_graph(b);
                    self.graph_ops.extend(ops);
                    self.tensors.extend(tensors);
                }
                (8, Field::Len(b)) => {
                    // OperatorSetIdProto: 1=domain(str), 2=version(varint)
                    let mut o = Reader::new(b);
                    let (mut domain, mut version) = (String::new(), 0u64);
                    while let Some((f, v)) = o.next_field() {
                        match (f, v) {
                            (1, Field::Len(bb)) => domain = as_string(bb).unwrap_or_default(),
                            (2, Field::Varint(n)) => version = n,
                            _ => {}
                        }
                    }
                    let dom = if domain.is_empty() {
                        "ai.onnx"
                    } else {
                        &domain
                    };
                    self.metadata
                        .push(("onnx.opset".into(), format!("{dom} v{version}")));
                }
                (14, Field::Len(b)) => {
                    if let Some((k, v)) = parse_string_string_entry(b) {
                        self.metadata.push((format!("onnx.meta.{k}"), v));
                    }
                }
                _ => {}
            }
        }
        self.tensor_count = Some(self.tensors.len() as u64);
    }

    // ---- TensorFlow SavedModel / GraphDef (protobuf) --------------------

    fn parse_tensorflow(&mut self) {
        // TensorFlow's SavedModel/MetaGraphDef schema is deep and version-
        // dependent, so instead of modelling it we do a bounded, depth-limited
        // walk of the protobuf wire format, harvesting operator names (NodeDef
        // field 2 = "op") and any printable metadata strings. This is enough to
        // feed the operator scanner without a schema dependency.
        let data = self.map.as_ref();
        let mut ops = Vec::new();
        let mut strings = Vec::new();
        harvest_pb(data, 0, &mut ops, &mut strings);
        ops.sort();
        ops.dedup();
        for op in ops.into_iter().take(100_000) {
            self.graph_ops.push(op);
        }
        // A handful of the most descriptive strings become metadata entries so
        // the secrets/pii/metadata scanners can inspect them too.
        for s in strings.into_iter().take(256) {
            self.metadata.push(("tf.string".into(), s));
        }
    }

    // ---- NumPy / MLX .npz ----------------------------------------------

    fn parse_npz(&mut self) {
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
            let name = entry.name().trim_end_matches(".npy").to_string();
            let mut buf = Vec::new();
            if entry.read_to_end(&mut buf).is_err() {
                continue;
            }
            if let Some((dtype, shape)) = parse_npy_header(&buf) {
                // Object arrays ('|O') serialize their elements as pickle, which
                // is code-execution on `np.load(allow_pickle=True)`. Route the
                // payload to the pickle scanner.
                if dtype.contains('O') {
                    if let Some(pos) = buf.iter().position(|&b| b == 0x80) {
                        self.pickles.push(PickleStream {
                            name: format!("npz:{name}.npy"),
                            bytes: buf[pos..].to_vec(),
                        });
                    }
                }
                self.tensors.push(TensorDesc {
                    name,
                    dtype,
                    shape,
                    data: None,
                });
            }
        }
        self.tensor_count = Some(self.tensors.len() as u64);
    }

    // ---- Hugging Face / diffusers JSON config ---------------------------

    fn parse_hf_config(&mut self) {
        // Reject absurdly large configs before handing bytes to serde_json; a
        // genuine config is kilobytes, and we must not let a hostile multi-GB
        // ".json" exhaust memory during parsing.
        const MAX_CONFIG: usize = 16 * 1024 * 1024;
        if self.map.len() > MAX_CONFIG {
            return;
        }
        let value: serde_json::Value = match serde_json::from_slice(self.map.as_ref()) {
            Ok(v) => v,
            Err(_) => return,
        };
        // Flatten string leaves into metadata so the secrets/pii/metadata
        // scanners inspect config values too (keys and paths leak here). Bounded
        // in count and per-value length so a pathological config can't blow up.
        let mut budget = 512usize;
        flatten_json_strings(&value, String::new(), &mut self.metadata, &mut budget);
        self.config = Some(value);
    }

    // ---- Datasets (CSV / TSV / JSONL) -----------------------------------

    /// Parse a delimited (CSV/TSV) dataset from a bounded prefix of the file:
    /// the first line is the header, subsequent lines are sampled into rows.
    fn parse_delimited(&mut self, delim: u8) {
        let kind = if delim == b'\t' { "tsv" } else { "csv" };
        let (text, truncated) = self.sample_text();
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());

        let header = match lines.next() {
            Some(h) => h,
            None => return,
        };
        let col_names: Vec<String> = split_delimited(header, delim)
            .into_iter()
            .take(MAX_DATASET_COLS)
            .collect();
        if col_names.is_empty() {
            return;
        }

        let mut rows: Vec<Vec<(String, String)>> = Vec::new();
        for line in lines.take(MAX_DATASET_ROWS) {
            let fields = split_delimited(line, delim);
            let mut row = Vec::with_capacity(fields.len().min(MAX_DATASET_COLS));
            for (i, mut v) in fields.into_iter().take(MAX_DATASET_COLS).enumerate() {
                truncate_in_place(&mut v, MAX_FIELD_LEN);
                let name = col_names
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| format!("col{i}"));
                row.push((name, v));
            }
            rows.push(row);
        }

        let columns = infer_columns(&col_names, &rows);
        let rows_scanned = rows.len();
        self.dataset = Some(DatasetInfo {
            kind,
            columns,
            rows,
            rows_scanned,
            truncated,
        });
    }

    /// Parse a JSON Lines dataset: each non-empty line is one JSON value. Object
    /// lines contribute their keys as columns; other values fold into a single
    /// `value` column.
    fn parse_jsonl(&mut self) {
        let (text, truncated) = self.sample_text();
        let mut rows: Vec<Vec<(String, String)>> = Vec::new();
        let mut col_order: Vec<String> = Vec::new();

        for line in text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .take(MAX_DATASET_ROWS)
        {
            let value: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mut row = Vec::new();
            match value {
                serde_json::Value::Object(map) => {
                    for (k, v) in map.into_iter().take(MAX_DATASET_COLS) {
                        if !col_order.iter().any(|c| c == &k) && col_order.len() < MAX_DATASET_COLS
                        {
                            col_order.push(k.clone());
                        }
                        let mut s = json_scalar_to_string(&v);
                        truncate_in_place(&mut s, MAX_FIELD_LEN);
                        row.push((k, s));
                    }
                }
                other => {
                    if !col_order.iter().any(|c| c == "value") {
                        col_order.push("value".to_string());
                    }
                    let mut s = json_scalar_to_string(&other);
                    truncate_in_place(&mut s, MAX_FIELD_LEN);
                    row.push(("value".to_string(), s));
                }
            }
            rows.push(row);
        }

        if col_order.is_empty() {
            return;
        }
        let columns = infer_columns(&col_order, &rows);
        let rows_scanned = rows.len();
        self.dataset = Some(DatasetInfo {
            kind: "jsonl",
            columns,
            rows,
            rows_scanned,
            truncated,
        });
    }

    /// A UTF-8 (lossy) copy of the leading sample window, plus whether the file
    /// extends beyond it.
    fn sample_text(&self) -> (String, bool) {
        let n = self.map.len().min(DATASET_SAMPLE_BYTES);
        let truncated = self.map.len() > DATASET_SAMPLE_BYTES;
        (
            String::from_utf8_lossy(&self.map[..n]).into_owned(),
            truncated,
        )
    }
}

/// Bytes of a dataset file to sample from the start (4 MiB).
const DATASET_SAMPLE_BYTES: usize = 4 * 1024 * 1024;
/// Max rows retained from the sample window.
const MAX_DATASET_ROWS: usize = 2000;
/// Max columns tracked.
const MAX_DATASET_COLS: usize = 512;
/// Max retained length of a single field value.
const MAX_FIELD_LEN: usize = 2048;

/// Split one delimited line into fields, honoring double-quoted fields that may
/// contain the delimiter (`""` is an escaped quote). Not full RFC-4180 (no
/// embedded newlines), which is deliberate — we parse a bounded line-oriented
/// sample, not the entire file.
fn split_delimited(line: &str, delim: u8) -> Vec<String> {
    let delim = delim as char;
    let mut out = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == delim {
            out.push(std::mem::take(&mut field));
        } else {
            field.push(c);
        }
    }
    out.push(field);
    out.into_iter().map(|f| f.trim().to_string()).collect()
}

/// Render a JSON value as a compact string for field-level scanning.
fn json_scalar_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Truncate a string in place to at most `max` chars (char-boundary safe).
fn truncate_in_place(s: &mut String, max: usize) {
    if s.chars().count() > max {
        *s = s.chars().take(max).collect();
    }
}

/// Infer a coarse type per column from the sampled values.
fn infer_columns(names: &[String], rows: &[Vec<(String, String)>]) -> Vec<DatasetColumn> {
    names
        .iter()
        .map(|name| {
            let mut all_int = true;
            let mut all_float = true;
            let mut all_bool = true;
            let mut seen = 0usize;
            for row in rows {
                if let Some((_, v)) = row.iter().find(|(c, _)| c == name) {
                    if v.is_empty() {
                        continue;
                    }
                    seen += 1;
                    if v.parse::<i64>().is_err() {
                        all_int = false;
                    }
                    if v.parse::<f64>().is_err() {
                        all_float = false;
                    }
                    if !matches!(v.to_ascii_lowercase().as_str(), "true" | "false") {
                        all_bool = false;
                    }
                }
            }
            let inferred_type = if seen == 0 {
                "empty"
            } else if all_int {
                "int"
            } else if all_bool {
                "bool"
            } else if all_float {
                "float"
            } else {
                "string"
            };
            DatasetColumn {
                name: name.clone(),
                inferred_type: inferred_type.to_string(),
            }
        })
        .collect()
}

/// Collect string leaves of a JSON value into `out` as `(dotted.path, value)`
/// pairs, bounded by `budget` entries and truncating each value. Array elements
/// use their index as a path segment.
fn flatten_json_strings(
    value: &serde_json::Value,
    path: String,
    out: &mut Vec<(String, String)>,
    budget: &mut usize,
) {
    if *budget == 0 {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            let key = if path.is_empty() {
                "config".into()
            } else {
                path
            };
            let v: String = s.chars().take(4096).collect();
            out.push((key, v));
            *budget -= 1;
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if *budget == 0 {
                    break;
                }
                let child = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                flatten_json_strings(v, child, out, budget);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                if *budget == 0 {
                    break;
                }
                flatten_json_strings(v, format!("{path}.{i}"), out, budget);
            }
        }
        _ => {}
    }
}

/// Parse an ONNX GraphProto, returning `(operator names, tensor descriptors)`.
fn parse_onnx_graph(b: &[u8]) -> (Vec<String>, Vec<TensorDesc>) {
    use crate::pb::{as_string, Field, Reader};
    let mut ops = Vec::new();
    let mut tensors = Vec::new();
    // GraphProto: 1=node (NodeProto), 5=initializer (TensorProto).
    let mut g = Reader::new(b);
    while let Some((field, val)) = g.next_field() {
        match (field, val) {
            (1, Field::Len(node)) => {
                // NodeProto: 4=op_type(str), 7=domain(str)
                let mut n = Reader::new(node);
                let (mut op, mut domain) = (String::new(), String::new());
                while let Some((f, v)) = n.next_field() {
                    match (f, v) {
                        (4, Field::Len(bb)) => op = as_string(bb).unwrap_or_default(),
                        (7, Field::Len(bb)) => domain = as_string(bb).unwrap_or_default(),
                        _ => {}
                    }
                }
                if !op.is_empty() && ops.len() < 100_000 {
                    let qualified = if domain.is_empty() || domain == "ai.onnx" {
                        op
                    } else {
                        format!("{domain}.{op}")
                    };
                    ops.push(qualified);
                }
            }
            (5, Field::Len(t)) => {
                // TensorProto: 1=dims(repeated varint), 2=data_type, 8=name
                let mut tr = Reader::new(t);
                let (mut dims, mut dtype, mut name) = (Vec::new(), 0u64, String::new());
                while let Some((f, v)) = tr.next_field() {
                    match (f, v) {
                        (1, Field::Varint(d)) => dims.push(d),
                        (2, Field::Varint(dt)) => dtype = dt,
                        (8, Field::Len(bb)) => name = as_string(bb).unwrap_or_default(),
                        _ => {}
                    }
                }
                if tensors.len() < 1_000_000 {
                    tensors.push(TensorDesc {
                        name,
                        dtype: onnx_dtype_name(dtype).to_string(),
                        shape: dims,
                        data: None,
                    });
                }
            }
            _ => {}
        }
    }
    (ops, tensors)
}

/// Parse a StringStringEntryProto `{1=key, 2=value}`.
fn parse_string_string_entry(b: &[u8]) -> Option<(String, String)> {
    use crate::pb::{as_string, Field, Reader};
    let mut r = Reader::new(b);
    let (mut k, mut v) = (None, None);
    while let Some((f, val)) = r.next_field() {
        match (f, val) {
            (1, Field::Len(bb)) => k = as_string(bb),
            (2, Field::Len(bb)) => v = as_string(bb),
            _ => {}
        }
    }
    Some((k?, v.unwrap_or_default()))
}

/// Depth- and budget-bounded protobuf walk that harvests TensorFlow `NodeDef`
/// operator names and printable strings. Recurses into any length-delimited
/// field that itself parses as a nested message.
fn harvest_pb(b: &[u8], depth: u32, ops: &mut Vec<String>, strings: &mut Vec<String>) {
    use crate::pb::{as_string, Field, Reader};
    if depth > 12 || ops.len() + strings.len() > 200_000 {
        return;
    }
    let mut r = Reader::new(b);
    while let Some((field, val)) = r.next_field() {
        if let Field::Len(sub) = val {
            if let Some(s) = as_string(sub) {
                // NodeDef.op is field 2; heuristically treat short single-token
                // identifiers at field 2 as operator names, everything else as
                // a generic string.
                let looks_like_op = field == 2
                    && !s.is_empty()
                    && s.len() < 64
                    && s.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '/');
                if looks_like_op {
                    ops.push(s);
                } else if s.len() >= 4 && s.len() < 4096 {
                    strings.push(s);
                }
            } else if !sub.is_empty() {
                harvest_pb(sub, depth + 1, ops, strings);
            }
        }
    }
}

/// Parse a NumPy `.npy` header, returning `(dtype_descr, shape)`.
fn parse_npy_header(b: &[u8]) -> Option<(String, Vec<u64>)> {
    if b.len() < 10 || &b[0..6] != b"\x93NUMPY" {
        return None;
    }
    let major = b[6];
    let (hdr_len, hdr_start) = if major >= 2 {
        (
            u32::from_le_bytes(b.get(8..12)?.try_into().ok()?) as usize,
            12,
        )
    } else {
        (
            u16::from_le_bytes(b.get(8..10)?.try_into().ok()?) as usize,
            10,
        )
    };
    let header = std::str::from_utf8(b.get(hdr_start..hdr_start + hdr_len)?).ok()?;
    // header is a Python dict literal, e.g.
    // {'descr': '<f4', 'fortran_order': False, 'shape': (2, 3), }
    let dtype = extract_after(header, "'descr':").unwrap_or_else(|| "?".into());
    let shape = header
        .split_once("'shape':")
        .and_then(|(_, rest)| rest.split_once('('))
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(inner, _)| {
            inner
                .split(',')
                .filter_map(|t| t.trim().parse::<u64>().ok())
                .collect()
        })
        .unwrap_or_default();
    Some((dtype, shape))
}

/// Extract the first single-quoted token following `key` in a npy header dict.
fn extract_after(s: &str, key: &str) -> Option<String> {
    let rest = s.split_once(key)?.1;
    let start = rest.find('\'')? + 1;
    let end = rest[start..].find('\'')? + start;
    Some(rest[start..end].to_string())
}

/// Map a GGML tensor type id to a short name.
fn ggml_type_name(t: u32) -> &'static str {
    match t {
        0 => "f32",
        1 => "f16",
        2 => "q4_0",
        3 => "q4_1",
        6 => "q5_0",
        7 => "q5_1",
        8 => "q8_0",
        9 => "q8_1",
        10 => "q2_k",
        11 => "q3_k",
        12 => "q4_k",
        13 => "q5_k",
        14 => "q6_k",
        15 => "q8_k",
        24 => "i8",
        25 => "i16",
        26 => "i32",
        27 => "i64",
        28 => "f64",
        30 => "bf16",
        _ => "ggml_unknown",
    }
}

/// Map an ONNX TensorProto data-type enum to a short name.
fn onnx_dtype_name(t: u64) -> &'static str {
    match t {
        1 => "f32",
        2 => "u8",
        3 => "i8",
        4 => "u16",
        5 => "i16",
        6 => "i32",
        7 => "i64",
        8 => "string",
        9 => "bool",
        10 => "f16",
        11 => "f64",
        12 => "u32",
        13 => "u64",
        16 => "bf16",
        _ => "?",
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
        0 | 1 | 7 => 1, // uint8 / int8 / bool
        2 | 3 => 2,     // uint16 / int16
        4..=6 => 4,     // uint32 / int32 / float32
        10..=12 => 8,   // uint64 / int64 / float64
        _ => return None,
    })
}
