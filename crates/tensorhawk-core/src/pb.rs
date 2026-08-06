//! Minimal, dependency-free protobuf wire-format reader.
//!
//! ONNX and TensorFlow SavedModel are Protocol Buffers with no framing magic.
//! We do not need the full schema — only enough of the wire format to pull out
//! the length-delimited strings and nested messages that carry security signal
//! (producer strings, metadata KV pairs, graph operator names). Everything is
//! bounds-checked and depth-bounded so a hostile message cannot make us loop,
//! recurse without limit, or read out of bounds.

/// A single protobuf field: its number and decoded value.
///
/// `Fixed64`/`Fixed32` carry their payloads for completeness even though the
/// current ONNX/TF extraction only consumes varints and length-delimited
/// fields; keeping them makes the reader a faithful, reusable wire decoder.
#[allow(dead_code)]
pub enum Field<'a> {
    Varint(u64),
    Fixed64(u64),
    Fixed32(u32),
    /// Length-delimited: a string, bytes, or a nested message.
    Len(&'a [u8]),
}

/// Forward-only reader over one protobuf message body.
pub struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }

    fn varint(&mut self) -> Option<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            if self.pos >= self.b.len() || shift >= 64 {
                return None;
            }
            let byte = self.b[self.pos];
            self.pos += 1;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Some(result);
            }
            shift += 7;
        }
    }

    /// Yield the next `(field_number, field)` pair, or `None` at end / on error.
    pub fn next_field(&mut self) -> Option<(u32, Field<'a>)> {
        if self.pos >= self.b.len() {
            return None;
        }
        let tag = self.varint()?;
        let field_no = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u32;
        let field = match wire {
            0 => Field::Varint(self.varint()?),
            1 => {
                let s = self.take(8)?;
                Field::Fixed64(u64::from_le_bytes(s.try_into().ok()?))
            }
            5 => {
                let s = self.take(4)?;
                Field::Fixed32(u32::from_le_bytes(s.try_into().ok()?))
            }
            2 => {
                let len = self.varint()? as usize;
                Field::Len(self.take(len)?)
            }
            _ => return None, // groups (3/4) are deprecated and unsupported
        };
        Some((field_no, field))
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
}

/// Interpret a length-delimited field as a UTF-8 string if it is printable.
pub fn as_string(b: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(b).ok()?;
    if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t') {
        Some(s.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_string_and_varint_fields() {
        // field 2 (LEN) = "hi", field 1 (VARINT) = 7
        let msg = [0x12, 0x02, b'h', b'i', 0x08, 0x07];
        let mut r = Reader::new(&msg);
        let (n, f) = r.next_field().unwrap();
        assert_eq!(n, 2);
        assert!(matches!(f, Field::Len(b) if b == b"hi"));
        let (n, f) = r.next_field().unwrap();
        assert_eq!(n, 1);
        assert!(matches!(f, Field::Varint(7)));
        assert!(r.next_field().is_none());
    }

    #[test]
    fn truncated_varint_is_none_not_panic() {
        let msg = [0x08, 0x80]; // varint continuation bit set, then EOF
        let mut r = Reader::new(&msg);
        assert!(r.next_field().is_none());
    }
}
