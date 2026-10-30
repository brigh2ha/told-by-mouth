//! A small deterministic CBOR encoder and strict decoder.
//!
//! Everything that is hashed or signed is encoded with this module, so every
//! phone hashes exactly the same bytes. We only use the subset we need:
//! unsigned and negative integers, byte strings, text strings, arrays, `null`
//! and booleans. Records are always arrays with a fixed field order (never
//! maps), which keeps the encoding deterministic without key sorting.
//!
//! The rules follow RFC 8949 section 4.2.1 (core deterministic encoding):
//! integers and lengths use the shortest form and indefinite lengths are
//! never used. The decoder rejects anything else, so one value has exactly
//! one encoding.

use crate::error::Error;

const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;

/// Deterministic CBOR writer.
#[derive(Default)]
pub struct Enc {
    buf: Vec<u8>,
}

impl Enc {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    fn head(&mut self, major: u8, value: u64) {
        let m = major << 5;
        if value < 24 {
            self.buf.push(m | value as u8);
        } else if value <= u8::MAX as u64 {
            self.buf.push(m | 24);
            self.buf.push(value as u8);
        } else if value <= u16::MAX as u64 {
            self.buf.push(m | 25);
            self.buf.extend_from_slice(&(value as u16).to_be_bytes());
        } else if value <= u32::MAX as u64 {
            self.buf.push(m | 26);
            self.buf.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            self.buf.push(m | 27);
            self.buf.extend_from_slice(&value.to_be_bytes());
        }
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.head(MAJOR_UINT, v);
        self
    }

    pub fn i64(&mut self, v: i64) -> &mut Self {
        if v >= 0 {
            self.head(MAJOR_UINT, v as u64);
        } else {
            // CBOR stores -1 - n for negative numbers.
            self.head(MAJOR_NINT, (-1 - v) as u64);
        }
        self
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.head(MAJOR_BYTES, b.len() as u64);
        self.buf.extend_from_slice(b);
        self
    }

    pub fn text(&mut self, s: &str) -> &mut Self {
        self.head(MAJOR_TEXT, s.len() as u64);
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    /// Starts an array of `len` items; the caller writes the items next.
    pub fn array(&mut self, len: usize) -> &mut Self {
        self.head(MAJOR_ARRAY, len as u64);
        self
    }

    pub fn null(&mut self) -> &mut Self {
        self.buf.push((MAJOR_SIMPLE << 5) | SIMPLE_NULL);
        self
    }

    pub fn bool(&mut self, b: bool) -> &mut Self {
        let v = if b { SIMPLE_TRUE } else { SIMPLE_FALSE };
        self.buf.push((MAJOR_SIMPLE << 5) | v);
        self
    }

    /// Appends an already encoded CBOR item.
    pub fn raw(&mut self, encoded: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(encoded);
        self
    }

    pub fn item<T: Cbor>(&mut self, v: &T) -> &mut Self {
        v.encode(self);
        self
    }

    pub fn opt<T: Cbor>(&mut self, v: &Option<T>) -> &mut Self {
        match v {
            Some(v) => v.encode(self),
            None => {
                self.null();
            }
        }
        self
    }

    pub fn opt_bytes(&mut self, v: Option<&[u8]>) -> &mut Self {
        match v {
            Some(b) => self.bytes(b),
            None => self.null(),
        }
    }

    pub fn list<T: Cbor>(&mut self, items: &[T]) -> &mut Self {
        self.array(items.len());
        for i in items {
            i.encode(self);
        }
        self
    }
}

/// Strict deterministic CBOR reader over a byte slice.
pub struct Dec<'a> {
    data: &'a [u8],
    pos: usize,
}

fn err(what: &str) -> Error {
    Error::Decode(what.to_string())
}

impl<'a> Dec<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Fails unless every byte was consumed.
    pub fn finish(&self) -> Result<(), Error> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(err("trailing bytes"))
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| err("length overflow"))?;
        if end > self.data.len() {
            return Err(err("unexpected end"));
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn peek(&self) -> Result<u8, Error> {
        self.data
            .get(self.pos)
            .copied()
            .ok_or_else(|| err("unexpected end"))
    }

    fn head(&mut self) -> Result<(u8, u64), Error> {
        let b = self.take(1)?[0];
        let major = b >> 5;
        let info = b & 0x1f;
        let value = match info {
            0..=23 => return Ok((major, info as u64)),
            24 => {
                let v = self.take(1)?[0] as u64;
                if v < 24 {
                    return Err(err("non-shortest integer"));
                }
                v
            }
            25 => {
                let v = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if v <= u8::MAX as u64 {
                    return Err(err("non-shortest integer"));
                }
                v
            }
            26 => {
                let v = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if v <= u16::MAX as u64 {
                    return Err(err("non-shortest integer"));
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if v <= u32::MAX as u64 {
                    return Err(err("non-shortest integer"));
                }
                v
            }
            _ => return Err(err("indefinite or reserved length")),
        };
        Ok((major, value))
    }

    fn expect_head(&mut self, major: u8, what: &str) -> Result<u64, Error> {
        let (m, v) = self.head()?;
        if m != major {
            return Err(err(&format!("expected {what}")));
        }
        Ok(v)
    }

    pub fn u64(&mut self) -> Result<u64, Error> {
        self.expect_head(MAJOR_UINT, "unsigned integer")
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        u32::try_from(self.u64()?).map_err(|_| err("integer too large"))
    }

    pub fn u16(&mut self) -> Result<u16, Error> {
        u16::try_from(self.u64()?).map_err(|_| err("integer too large"))
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        u8::try_from(self.u64()?).map_err(|_| err("integer too large"))
    }

    pub fn i64(&mut self) -> Result<i64, Error> {
        let (m, v) = self.head()?;
        match m {
            MAJOR_UINT => i64::try_from(v).map_err(|_| err("integer too large")),
            MAJOR_NINT => {
                let n = i64::try_from(v).map_err(|_| err("integer too small"))?;
                Ok(-1 - n)
            }
            _ => Err(err("expected integer")),
        }
    }

    pub fn i32(&mut self) -> Result<i32, Error> {
        i32::try_from(self.i64()?).map_err(|_| err("integer out of range"))
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let len = self.expect_head(MAJOR_BYTES, "byte string")?;
        self.take(usize::try_from(len).map_err(|_| err("too long"))?)
    }

    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.bytes()?
            .try_into()
            .map_err(|_| err(&format!("expected {N} bytes")))
    }

    pub fn text(&mut self) -> Result<&'a str, Error> {
        let len = self.expect_head(MAJOR_TEXT, "text string")?;
        let raw = self.take(usize::try_from(len).map_err(|_| err("too long"))?)?;
        std::str::from_utf8(raw).map_err(|_| err("invalid UTF-8"))
    }

    pub fn string(&mut self) -> Result<String, Error> {
        self.text().map(str::to_owned)
    }

    /// Reads an array head and returns its length.
    pub fn array(&mut self) -> Result<usize, Error> {
        let len = self.expect_head(MAJOR_ARRAY, "array")?;
        // Every item takes at least one byte, which bounds allocations.
        if len > (self.data.len() - self.pos) as u64 {
            return Err(err("array longer than input"));
        }
        Ok(len as usize)
    }

    /// Reads an array head that must have exactly `n` items.
    pub fn expect_array(&mut self, n: usize) -> Result<(), Error> {
        if self.array()? != n {
            return Err(err(&format!("expected array of {n}")));
        }
        Ok(())
    }

    /// Consumes a `null` if it is next and returns true.
    pub fn null(&mut self) -> Result<bool, Error> {
        if self.peek()? == (MAJOR_SIMPLE << 5) | SIMPLE_NULL {
            self.pos += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn bool(&mut self) -> Result<bool, Error> {
        let b = self.take(1)?[0];
        match b {
            x if x == (MAJOR_SIMPLE << 5) | SIMPLE_TRUE => Ok(true),
            x if x == (MAJOR_SIMPLE << 5) | SIMPLE_FALSE => Ok(false),
            _ => Err(err("expected bool")),
        }
    }

    pub fn item<T: Cbor>(&mut self) -> Result<T, Error> {
        T::decode(self)
    }

    pub fn opt<T: Cbor>(&mut self) -> Result<Option<T>, Error> {
        if self.null()? {
            Ok(None)
        } else {
            T::decode(self).map(Some)
        }
    }

    pub fn opt_bytes(&mut self) -> Result<Option<&'a [u8]>, Error> {
        if self.null()? {
            Ok(None)
        } else {
            self.bytes().map(Some)
        }
    }

    pub fn list<T: Cbor>(&mut self) -> Result<Vec<T>, Error> {
        let n = self.array()?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(T::decode(self)?);
        }
        Ok(out)
    }
}

/// A value with one fixed CBOR encoding.
pub trait Cbor: Sized {
    fn encode(&self, e: &mut Enc);
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error>;

    fn to_cbor(&self) -> Vec<u8> {
        let mut e = Enc::new();
        self.encode(&mut e);
        e.finish()
    }

    /// Decodes exactly one value; trailing bytes are an error.
    fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Dec::new(bytes);
        let v = Self::decode(&mut d)?;
        d.finish()?;
        Ok(v)
    }
}

impl<const N: usize> Cbor for [u8; N] {
    fn encode(&self, e: &mut Enc) {
        e.bytes(self);
    }
    fn decode(d: &mut Dec<'_>) -> Result<Self, Error> {
        d.fixed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(f: impl FnOnce(&mut Enc)) -> Vec<u8> {
        let mut e = Enc::new();
        f(&mut e);
        e.finish()
    }

    #[test]
    fn integers_use_shortest_form() {
        assert_eq!(
            enc(|e| {
                e.u64(0);
            }),
            [0x00]
        );
        assert_eq!(
            enc(|e| {
                e.u64(23);
            }),
            [0x17]
        );
        assert_eq!(
            enc(|e| {
                e.u64(24);
            }),
            [0x18, 24]
        );
        assert_eq!(
            enc(|e| {
                e.u64(256);
            }),
            [0x19, 1, 0]
        );
        assert_eq!(
            enc(|e| {
                e.u64(65536);
            }),
            [0x1a, 0, 1, 0, 0]
        );
        assert_eq!(
            enc(|e| {
                e.u64(1 << 32);
            }),
            [0x1b, 0, 0, 0, 1, 0, 0, 0, 0]
        );
        assert_eq!(
            enc(|e| {
                e.i64(-1);
            }),
            [0x20]
        );
        assert_eq!(
            enc(|e| {
                e.i64(-500);
            }),
            [0x39, 0x01, 0xf3]
        );
    }

    #[test]
    fn round_trips_every_kind() {
        let bytes = enc(|e| {
            e.array(7)
                .u64(1_700_000_000)
                .i64(-37_123_456)
                .bytes(&[1, 2, 3])
                .text("국수")
                .null()
                .bool(true)
                .i64(i32::MIN as i64);
        });
        let mut d = Dec::new(&bytes);
        d.expect_array(7).unwrap();
        assert_eq!(d.u64().unwrap(), 1_700_000_000);
        assert_eq!(d.i32().unwrap(), -37_123_456);
        assert_eq!(d.bytes().unwrap(), &[1, 2, 3]);
        assert_eq!(d.text().unwrap(), "국수");
        assert!(d.null().unwrap());
        assert!(d.bool().unwrap());
        assert_eq!(d.i32().unwrap(), i32::MIN);
        d.finish().unwrap();
    }

    #[test]
    fn rejects_non_canonical_and_garbage() {
        // 5 encoded with a one-byte length.
        assert!(Dec::new(&[0x18, 5]).u64().is_err());
        // 200 encoded with two bytes.
        assert!(Dec::new(&[0x19, 0, 200]).u64().is_err());
        // Indefinite-length byte string.
        assert!(Dec::new(&[0x5f]).bytes().is_err());
        // Truncated.
        assert!(Dec::new(&[0x43, 1, 2]).bytes().is_err());
        // Invalid UTF-8.
        assert!(Dec::new(&[0x61, 0xff]).text().is_err());
        // Array claiming more items than bytes.
        assert!(Dec::new(&[0x9a, 0xff, 0xff, 0xff, 0xff]).array().is_err());
        // Trailing bytes.
        assert!(<[u8; 1]>::from_cbor(&[0x41, 7, 0]).is_err());
        assert_eq!(<[u8; 1]>::from_cbor(&[0x41, 7]).unwrap(), [7]);
    }
}
