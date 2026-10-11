//! TagField: the `key=value` payload text carried by FESL, Theater and Messenger frames.
//!
//! Mirrored from the client's DirtySock TagField routines (`0x9cc000`–`0x9cc820`):
//!
//! * **Encoder** (`FUN_009cc820` strings, `FUN_009cc370` integers): every field is `key=value` followed by
//!   `\n` (`DAT_00cdec50`). Setting an existing key removes it and appends the new value at the end
//!   (`FUN_009cc000`), so emit order is the order of the last set. A string containing `' '` or `','` is
//!   wrapped in `"…"`. Bytes flagged in the table at `0xb67348` — 0x00–0x1F, `"`, `%`, `=`, 0x7F — are written
//!   as `%xx` with lowercase hex (`0xb67448`). Everything else, including 0x80–0xFF, is written raw.
//! * **Key lookup** (`FUN_009cc1e0`): case-insensitive (ASCII upper-fold table `0xb67558`); a key matches at
//!   the start of the buffer, or where the byte before it is `< 0x21`, and must be immediately followed by
//!   `=`. The first match wins. If the byte before a candidate `=` is `< 0x21` the whole lookup fails.
//! * **Value read** (`FUN_009cc4e0`): a leading `"` reads to the next `"`; otherwise the value ends at the
//!   first space. Either way it also ends at any byte `< 0x20`. `%%` decodes to `%`; `%XX` decodes as hex
//!   (table `0xb67458`).
//! * **Integers** (`FUN_009cc470`): optional `-` / `+`, `$` prefix for hex, decimal otherwise.
//!
//! Where the client is lenient about malformed input it never produces (non-hex `%` escapes, non-numeric
//! integers) this server-side reader is strict and returns an error instead.

use thiserror::Error;

const SEPARATOR: u8 = b'\n';

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TagFieldError {
    #[error("key {0:?} is not a valid TagField key (must be non-empty, printable ASCII, no '=')")]
    BadKey(String),
    #[error("value of {key:?} has a malformed %-escape at byte {offset}")]
    BadEscape { key: String, offset: usize },
    #[error("value of {key:?} is not an integer: {value:?}")]
    NotAnInteger { key: String, value: String },
    #[error("value of {key:?} is not valid UTF-8")]
    NotUtf8 { key: String },
}

fn is_escaped(b: u8) -> bool {
    // Bit 0 of DAT_00b67348, dumped from the exe.
    b < 0x20 || b == b'"' || b == b'%' || b == b'=' || b == 0x7f
}

fn validate_key(key: &str) -> Result<(), TagFieldError> {
    let ok = !key.is_empty() && key.bytes().all(|b| b > 0x20 && b < 0x7f && b != b'=' && b != b'"');
    if ok { Ok(()) } else { Err(TagFieldError::BadKey(key.to_owned())) }
}

/// Encode a string value exactly as `FUN_009cc820` does.
pub fn encode_str_value(value: &[u8]) -> Vec<u8> {
    let quoted = value.iter().any(|&b| b == b' ' || b == b',');
    let mut out = Vec::with_capacity(value.len() + 2);
    if quoted {
        out.push(b'"');
    }
    for &b in value {
        if is_escaped(b) {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            out.extend_from_slice(&[b'%', HEX[(b >> 4) as usize], HEX[(b & 0xf) as usize]]);
        } else {
            out.push(b);
        }
    }
    if quoted {
        out.push(b'"');
    }
    out
}

/// An ordered TagField message being built.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TagFields {
    fields: Vec<(String, Vec<u8>)>,
}

impl TagFields {
    pub fn new() -> Self {
        Self::default()
    }

    fn set_encoded(&mut self, key: &str, encoded: Vec<u8>) -> Result<&mut Self, TagFieldError> {
        validate_key(key)?;
        self.fields.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
        self.fields.push((key.to_owned(), encoded));
        Ok(self)
    }

    /// Set a string value (bytes; 0x80–0xFF are passed through raw like the client does).
    pub fn set_str(&mut self, key: &str, value: impl AsRef<[u8]>) -> Result<&mut Self, TagFieldError> {
        self.set_encoded(key, encode_str_value(value.as_ref()))
    }

    /// Set a signed decimal integer (`FUN_009cc370`; 64-bit values use `%I64d` in the client).
    pub fn set_int(&mut self, key: &str, value: i64) -> Result<&mut Self, TagFieldError> {
        self.set_encoded(key, value.to_string().into_bytes())
    }

    /// Set a list in the client's flattened form: `name.[]=N` followed by whatever the caller writes under
    /// `name.<i>.…` via `item`.
    pub fn set_list<T>(
        &mut self,
        name: &str,
        items: &[T],
        mut item: impl FnMut(&mut Self, &str, &T) -> Result<(), TagFieldError>,
    ) -> Result<&mut Self, TagFieldError> {
        self.set_int(&format!("{name}.[]"), items.len() as i64)?;
        for (i, it) in items.iter().enumerate() {
            item(self, &format!("{name}.{i}"), it)?;
        }
        Ok(self)
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The TagField text without the trailing NUL (`key=value\n` per field).
    pub fn to_text(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in &self.fields {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v);
            out.push(SEPARATOR);
        }
        out
    }

    /// The frame payload: the text plus the trailing NUL every client frame carries (`FUN_00970400`).
    pub fn to_payload(&self) -> Vec<u8> {
        let mut out = self.to_text();
        out.push(0);
        out
    }
}

/// Read-only view over a received TagField payload, using the client's lookup semantics.
#[derive(Clone, Copy, Debug)]
pub struct TagFieldReader<'a> {
    text: &'a [u8],
}

impl<'a> TagFieldReader<'a> {
    /// Wrap a frame payload. Parsing stops at the first NUL, as the client's C-string routines do.
    pub fn new(payload: &'a [u8]) -> Self {
        let end = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
        TagFieldReader { text: &payload[..end] }
    }

    /// Offset of the value for `key`, following `FUN_009cc1e0` exactly.
    fn find(&self, key: &str) -> Option<usize> {
        let buf = self.text;
        let k = key.as_bytes();
        if k.is_empty() || buf.is_empty() || buf.len() < k.len() {
            return None;
        }
        if buf[..k.len()].eq_ignore_ascii_case(k) && buf.get(k.len()) == Some(&b'=') {
            return Some(k.len() + 1);
        }
        for p in (k.len() + 1)..buf.len() {
            if buf[p] != b'=' {
                continue;
            }
            if buf[p - 1] < 0x21 {
                return None;
            }
            let start = p - k.len();
            if buf[start - 1] < 0x21 && buf[start..p].eq_ignore_ascii_case(k) {
                return Some(p + 1);
            }
        }
        None
    }

    /// The raw (still-escaped) bytes of the value, bounded as `FUN_009cc4e0` bounds them.
    fn raw_value(&self, key: &str) -> Option<(&'a [u8], bool)> {
        let at = self.find(key)?;
        let rest = &self.text[at..];
        let (body, term) = match rest.first() {
            Some(b'"') => (&rest[1..], b'"'),
            _ => (rest, b' '),
        };
        let end = body.iter().position(|&b| b == term || b < 0x20).unwrap_or(body.len());
        Some((&body[..end], term == b'"'))
    }

    pub fn contains(&self, key: &str) -> bool {
        self.find(key).is_some()
    }

    /// Decoded value bytes, or `None` if the key is absent.
    pub fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, TagFieldError> {
        let Some((raw, _)) = self.raw_value(key) else { return Ok(None) };
        let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
        let mut out = Vec::with_capacity(raw.len());
        let mut i = 0;
        while i < raw.len() {
            if raw[i] != b'%' {
                out.push(raw[i]);
                i += 1;
                continue;
            }
            if raw.get(i + 1) == Some(&b'%') {
                out.push(b'%');
                i += 2;
                continue;
            }
            match (raw.get(i + 1).copied().and_then(hex), raw.get(i + 2).copied().and_then(hex)) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                }
                _ => return Err(TagFieldError::BadEscape { key: key.to_owned(), offset: i }),
            }
        }
        Ok(Some(out))
    }

    /// Decoded value as UTF-8 text, or `None` if the key is absent.
    pub fn get_str(&self, key: &str) -> Result<Option<String>, TagFieldError> {
        match self.get_bytes(key)? {
            None => Ok(None),
            Some(b) => String::from_utf8(b)
                .map(Some)
                .map_err(|_| TagFieldError::NotUtf8 { key: key.to_owned() }),
        }
    }

    /// Integer value (`FUN_009cc470` grammar: optional sign, `$` for hex), or `None` if absent.
    pub fn get_int(&self, key: &str) -> Result<Option<i64>, TagFieldError> {
        let Some(s) = self.get_str(key)? else { return Ok(None) };
        let bad = || TagFieldError::NotAnInteger { key: key.to_owned(), value: s.clone() };
        let (neg, digits, radix) = match s.as_bytes().first() {
            Some(b'-') => (true, &s[1..], 10),
            Some(b'+') => (false, &s[1..], 10),
            Some(b'$') => (false, &s[1..], 16),
            _ => (false, &s[..], 10),
        };
        if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
            return Err(bad());
        }
        let v = i64::from_str_radix(digits, radix).map_err(|_| bad())?;
        Ok(Some(if neg { -v } else { v }))
    }

    /// Keys of every `key=value` line, in order, for callers that must collect a family of keys (`B-U-*`,
    /// `D-*`, `P-*`, `players.0.props.{filter-*}`). Lines are split at `\n`, the separator the client's
    /// encoder writes (`DAT_00cdec50`); the key is the text before the line's first `=`. Values must still be
    /// read through the typed getters. A line without `=` or with a non-UTF-8 / invalid key is an error.
    pub fn keys(&self) -> Result<Vec<String>, TagFieldError> {
        let mut out = Vec::new();
        for line in self.text.split(|&b| b == SEPARATOR).filter(|l| !l.is_empty()) {
            let eq = line.iter().position(|&b| b == b'=');
            let key = eq.and_then(|i| std::str::from_utf8(&line[..i]).ok());
            match key {
                Some(k) if validate_key(k).is_ok() => out.push(k.to_owned()),
                _ => return Err(TagFieldError::BadKey(String::from_utf8_lossy(line).into_owned())),
            }
        }
        Ok(out)
    }

    /// Every `key=value` line in order, undecoded — for logging and diagnostics only. Protocol logic must go
    /// through the typed getters, which implement the client's lookup rules.
    pub fn lines(&self) -> impl Iterator<Item = &'a [u8]> {
        self.text.split(|&b| b == SEPARATOR).filter(|l| !l.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_matches_client_rules() {
        let mut t = TagFields::new();
        t.set_str("TXN", "Hello").unwrap();
        t.set_str("NAME", "foo bar").unwrap();
        t.set_str("eq", "a=b%c\"d").unwrap();
        t.set_int("n", -42).unwrap();
        assert_eq!(t.to_payload(), b"TXN=Hello\nNAME=\"foo bar\"\neq=a%3db%25c%22d\nn=-42\n\0".to_vec());
    }

    #[test]
    fn comma_triggers_quoting_and_high_bytes_pass_raw() {
        assert_eq!(encode_str_value(b"a,b"), b"\"a,b\"".to_vec());
        assert_eq!(encode_str_value(&[0xe9, b'\n']), vec![0xe9, b'%', b'0', b'a']);
    }

    #[test]
    fn set_replaces_and_moves_to_end() {
        let mut t = TagFields::new();
        t.set_int("a", 1).unwrap().set_int("b", 2).unwrap().set_int("A", 3).unwrap();
        assert_eq!(t.to_text(), b"b=2\nA=3\n".to_vec());
    }

    #[test]
    fn list_flattening() {
        let mut t = TagFields::new();
        t.set_list("pingSite", &["iad", "sjc"], |t, p, name| {
            t.set_str(&format!("{p}.name"), name)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(t.to_text(), b"pingSite.[]=2\npingSite.0.name=iad\npingSite.1.name=sjc\n".to_vec());
    }

    #[test]
    fn reader_round_trips_encoder() {
        let mut t = TagFields::new();
        t.set_str("TXN", "NuLogin").unwrap();
        t.set_str("nuid", "foo bar,baz").unwrap();
        t.set_str("pw", "p=%\"w").unwrap();
        t.set_int("tid", 7).unwrap();
        let payload = t.to_payload();
        let r = TagFieldReader::new(&payload);
        assert_eq!(r.get_str("txn").unwrap().as_deref(), Some("NuLogin"));
        assert_eq!(r.get_str("nuid").unwrap().as_deref(), Some("foo bar,baz"));
        assert_eq!(r.get_str("pw").unwrap().as_deref(), Some("p=%\"w"));
        assert_eq!(r.get_int("TID").unwrap(), Some(7));
        assert_eq!(r.get_str("missing").unwrap(), None);
    }

    #[test]
    fn reader_lookup_requires_separator_before_key() {
        // "xTID=5" must not satisfy a lookup of "TID".
        let r = TagFieldReader::new(b"xTID=5\nTID=6\n\0");
        assert_eq!(r.get_int("TID").unwrap(), Some(6));
    }

    #[test]
    fn reader_first_match_wins_and_any_whitespace_separates() {
        let r = TagFieldReader::new(b"a=1\r\n\ta=2 a=3\0");
        assert_eq!(r.get_int("a").unwrap(), Some(1));
    }

    #[test]
    fn reader_unquoted_value_stops_at_space() {
        let r = TagFieldReader::new(b"NAME=foo bar\n\0");
        assert_eq!(r.get_str("NAME").unwrap().as_deref(), Some("foo"));
    }

    #[test]
    fn reader_integer_forms() {
        let r = TagFieldReader::new(b"a=$1F\nb=+12\nc=-3\nd=x1\n\0");
        assert_eq!(r.get_int("a").unwrap(), Some(31));
        assert_eq!(r.get_int("b").unwrap(), Some(12));
        assert_eq!(r.get_int("c").unwrap(), Some(-3));
        assert!(matches!(r.get_int("d"), Err(TagFieldError::NotAnInteger { .. })));
    }

    #[test]
    fn reader_rejects_malformed_escape() {
        let r = TagFieldReader::new(b"a=%zz\n\0");
        assert!(matches!(r.get_bytes("a"), Err(TagFieldError::BadEscape { .. })));
    }

    #[test]
    fn keys_in_order() {
        let r = TagFieldReader::new(b"LID=1\nB-U-mission=\"a b\"\nB-U-x=%3d\nTID=4\n\0");
        assert_eq!(r.keys().unwrap(), vec!["LID", "B-U-mission", "B-U-x", "TID"]);
        assert_eq!(r.get_str("B-U-x").unwrap().as_deref(), Some("="));
        assert!(TagFieldReader::new(b"novalue\n\0").keys().is_err());
    }

    #[test]
    fn bad_keys_are_refused() {
        assert!(TagFields::new().set_int("a b", 1).is_err());
        assert!(TagFields::new().set_int("a=b", 1).is_err());
        assert!(TagFields::new().set_int("", 1).is_err());
    }
}
