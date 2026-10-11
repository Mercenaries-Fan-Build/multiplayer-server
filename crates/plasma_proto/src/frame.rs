//! The 12-byte frame layer shared by FESL, Theater and Messenger.
//!
//! In the client this is DirtySock ProtoAries: send `FUN_009cd880`, receive/update `FUN_009cd3f0`.
//!
//! ```text
//! offset size field
//! 0x00   4    kind    big-endian u32; a 4CC whose ASCII bytes go out in order ('fsys' = 0x66737973)
//! 0x04   4    id      big-endian u32; meaning differs per service (see `fesl` / `theater`)
//! 0x08   4    length  big-endian u32; TOTAL frame length INCLUDING this 12-byte header
//! 0x0C   n    payload
//! ```
//!
//! The client computes `length = payload_len + 0xC` (`FUN_009cd880` → `FUN_009dacc0`, which adds 8 more only
//! when the optional `?tic`/`@tic` ticket cipher is active — it is off by default). On receive it closes the
//! connection when `length < 12` or `length` exceeds its buffer; there is no resynchronisation. This decoder
//! mirrors that: a bad length is a hard error, never a guess.

use thiserror::Error;

/// Size of the frame header in bytes.
pub const HEADER_LEN: usize = 12;

/// A 4CC frame kind, stored as the four ASCII bytes in wire order.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Kind(pub [u8; 4]);

impl Kind {
    pub const fn new(tag: &[u8; 4]) -> Self {
        Kind(*tag)
    }

    pub fn as_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
}

impl std::fmt::Debug for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.as_str() {
            Some(s) if self.0.iter().all(|b| b.is_ascii_graphic()) => write!(f, "Kind({s:?})"),
            _ => write!(f, "Kind(0x{:08x})", self.as_u32()),
        }
    }
}

/// One decoded frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub id: u32,
    /// The bytes after the header, exactly as on the wire (normally TagField text plus a trailing NUL).
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame length {0} is smaller than the 12-byte header")]
    LengthBelowHeader(u32),
    #[error("frame length {length} exceeds the configured maximum of {max} bytes")]
    TooLarge { length: u32, max: usize },
    #[error("payload of {0} bytes does not fit a u32 frame length")]
    PayloadTooLarge(usize),
}

/// Serialise one frame. `payload` is written verbatim; callers building TagField payloads should use
/// [`crate::tagfield::TagFields::to_payload`], which appends the trailing NUL the client always sends.
pub fn encode(kind: Kind, id: u32, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let total = payload
        .len()
        .checked_add(HEADER_LEN)
        .filter(|t| u32::try_from(*t).is_ok())
        .ok_or(FrameError::PayloadTooLarge(payload.len()))?;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&kind.0);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Incremental frame decoder for a byte stream.
///
/// The maximum frame size is a required parameter: the client's own limit is per-connection
/// (`ProtoAriesCreate(bufsize + 0x80)`), so the server must pick one deliberately for each service.
#[derive(Debug)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    max_frame: usize,
}

impl FrameDecoder {
    pub fn new(max_frame: usize) -> Self {
        FrameDecoder { buf: Vec::new(), max_frame }
    }

    /// Append bytes received from the stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes buffered but not yet returned as a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Return the next complete frame, `Ok(None)` if more bytes are needed, or an error if the stream is
    /// unrecoverable (the connection must then be closed — exactly what the client does).
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let length = u32::from_be_bytes(self.buf[8..12].try_into().expect("4-byte slice"));
        if (length as usize) < HEADER_LEN {
            return Err(FrameError::LengthBelowHeader(length));
        }
        if length as usize > self.max_frame {
            return Err(FrameError::TooLarge { length, max: self.max_frame });
        }
        if self.buf.len() < length as usize {
            return Ok(None);
        }
        let rest = self.buf.split_off(length as usize);
        let frame_bytes = std::mem::replace(&mut self.buf, rest);
        Ok(Some(Frame {
            kind: Kind(frame_bytes[0..4].try_into().expect("4-byte slice")),
            id: u32::from_be_bytes(frame_bytes[4..8].try_into().expect("4-byte slice")),
            payload: frame_bytes[HEADER_LEN..].to_vec(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_writes_total_length_including_header() {
        // FUN_009cd880: hdr[8..12] = BE(payload_len + 0xC).
        let bytes = encode(Kind::new(b"fsys"), 0xC000_0001, b"TXN=Hello\n\0").unwrap();
        assert_eq!(&bytes[0..4], b"fsys");
        assert_eq!(&bytes[4..8], &[0xC0, 0x00, 0x00, 0x01]);
        assert_eq!(u32::from_be_bytes(bytes[8..12].try_into().unwrap()), 12 + 11);
        assert_eq!(&bytes[12..], b"TXN=Hello\n\0");
    }

    #[test]
    fn decoder_round_trips_split_and_coalesced_frames() {
        let a = encode(Kind::new(b"fsys"), 1, b"TXN=Ping\n\0").unwrap();
        let b = encode(Kind::new(b"CONN"), 0, b"TID=1\n\0").unwrap();
        let mut stream = a.clone();
        stream.extend_from_slice(&b);

        let mut dec = FrameDecoder::new(8224);
        dec.feed(&stream[..5]);
        assert_eq!(dec.next_frame().unwrap(), None);
        dec.feed(&stream[5..]);
        let f1 = dec.next_frame().unwrap().unwrap();
        assert_eq!(f1.kind, Kind::new(b"fsys"));
        assert_eq!(f1.payload, b"TXN=Ping\n\0");
        let f2 = dec.next_frame().unwrap().unwrap();
        assert_eq!(f2.kind, Kind::new(b"CONN"));
        assert_eq!(dec.next_frame().unwrap(), None);
        assert_eq!(dec.buffered(), 0);
    }

    #[test]
    fn decoder_rejects_length_below_header() {
        let mut dec = FrameDecoder::new(8224);
        dec.feed(b"fsys\0\0\0\x01\0\0\0\x0b");
        assert_eq!(dec.next_frame(), Err(FrameError::LengthBelowHeader(11)));
    }

    #[test]
    fn decoder_rejects_oversized_frame_before_buffering_it() {
        let mut dec = FrameDecoder::new(64);
        dec.feed(b"fsys\0\0\0\x01\0\0\0\x41");
        assert_eq!(dec.next_frame(), Err(FrameError::TooLarge { length: 65, max: 64 }));
    }
}
