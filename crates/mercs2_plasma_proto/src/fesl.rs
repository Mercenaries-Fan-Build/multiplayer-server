//! FESL id word and multipart (chunked) messages.
//!
//! **Id word** (client codec vtable `0xb5faec`, composition at `0x976690`):
//! `id = (tid & 0xFFFFFF) | 0x80000000 | (multipart ? 0x30000000 : 0) | (request ? 0x40000000 : 0)`.
//! The client's tid is a per-connection counter starting at 1 (`FUN_00985480`). On receive it reads only
//! `tid = id & 0xFFFFFF` (`0x9764a0`) and the multipart bit `(id >> 29) & 1` (`0x9766c0`); a non-zero tid is
//! matched against pending requests, tid 0 goes straight to service dispatch (`FUN_009863a0`).
//!
//! **Multipart, client → server** (`FUN_0097ccb0`): when the TagField text is longer than the client's
//! `fragmentSize`, the whole text (without NUL) is base64-encoded and split into pieces of
//! `min(remaining, fragmentSize - 0x20)` characters; each piece is its own frame with id `0xF0000000 | tid`
//! and payload `size=<total base64 length>\ndata=<piece>\n` (with `=` escaped as `%3d`).
//!
//! **Multipart, server → client** (`FUN_009863a0` → `FUN_00985c80` → `FUN_00975f80`, decoder `FUN_009cd060`):
//! frames carry the multipart bit; the first part must carry `decodedSize=<decoded byte count>` (the client
//! allocates `decodedSize + 4` when it has no accumulator yet); every part carries `data=`. The decoder
//! rejects a `data` whose length is not a multiple of 4 and accepts padding only in a part's final quad, so
//! parts are split on 4-character boundaries with padding only in the last part. The message completes when
//! the decoded byte count reaches `decodedSize`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use thiserror::Error;

use crate::frame::{self, Frame, FrameError, Kind};
use crate::tagfield::{TagFieldError, TagFieldReader, TagFields};

pub const TID_MASK: u32 = 0x00FF_FFFF;
const BIT_ALWAYS: u32 = 0x8000_0000;
const BIT_REQUEST: u32 = 0x4000_0000;
const BITS_MULTIPART: u32 = 0x3000_0000;
const MULTIPART_TEST: u32 = 1 << 29;

/// Header bytes the client reserves per multipart piece (`fragmentSize - 0x20`).
const MULTIPART_OVERHEAD: usize = 0x20;

/// Decoded view of a FESL id word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeslId {
    pub tid: u32,
    pub multipart: bool,
}

impl FeslId {
    /// Decode the fields the client itself reads.
    pub fn decode(id: u32) -> Self {
        FeslId { tid: id & TID_MASK, multipart: id & MULTIPART_TEST != 0 }
    }

    /// Id for a server reply to a client request with this tid (`0x80000000 | tid`).
    pub fn reply(tid: u32) -> u32 {
        BIT_ALWAYS | (tid & TID_MASK)
    }

    /// Id for an unsolicited server push: tid 0, so it can never be mistaken for a pending request.
    pub fn push() -> u32 {
        BIT_ALWAYS
    }

    /// Id the client puts on its own requests (`0xC0000000 | tid`) — used by test clients.
    pub fn request(tid: u32) -> u32 {
        BIT_ALWAYS | BIT_REQUEST | (tid & TID_MASK)
    }

    fn multipart_reply(tid: u32) -> u32 {
        BIT_ALWAYS | BITS_MULTIPART | (tid & TID_MASK)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MultipartError {
    #[error("fragment size {0} leaves no room for a multipart piece (must exceed {MULTIPART_OVERHEAD} + 4)")]
    FragmentTooSmall(usize),
    #[error("multipart part is missing its {0} field")]
    MissingField(&'static str),
    #[error("multipart declared size changed mid-message ({first} then {now})")]
    SizeChanged { first: i64, now: i64 },
    #[error("multipart data exceeded the declared size {declared} (have {have})")]
    Overrun { declared: usize, have: usize },
    #[error("multipart declared size {0} is invalid")]
    BadSize(i64),
    #[error("multipart base64 does not decode: {0}")]
    Base64(String),
    #[error(transparent)]
    TagField(#[from] TagFieldError),
    #[error(transparent)]
    Frame(#[from] FrameError),
}

/// Encode a server reply, splitting it into multipart frames when its payload would exceed what the client
/// accepts in one frame.
///
/// `fragment_size` is the value the client advertised in its `fsys Hello` (`fragmentSize=`). A reply whose
/// payload (text + NUL) fits in `fragment_size` goes out as a single `0x80000000 | tid` frame.
pub fn encode_reply(kind: Kind, tid: u32, fields: &TagFields, fragment_size: usize) -> Result<Vec<Vec<u8>>, MultipartError> {
    let payload = fields.to_payload();
    if payload.len() <= fragment_size {
        return Ok(vec![frame::encode(kind, FeslId::reply(tid), &payload)?]);
    }
    let piece = fragment_size
        .checked_sub(MULTIPART_OVERHEAD)
        .map(|n| n / 4 * 4)
        .filter(|&n| n >= 4)
        .ok_or(MultipartError::FragmentTooSmall(fragment_size))?;
    let text = fields.to_text();
    let encoded = B64.encode(&text);
    let mut frames = Vec::new();
    for (i, chunk) in encoded.as_bytes().chunks(piece).enumerate() {
        let mut part = TagFields::new();
        if i == 0 {
            part.set_int("decodedSize", text.len() as i64)?;
        }
        part.set_str("data", chunk)?;
        frames.push(frame::encode(kind, FeslId::multipart_reply(tid), &part.to_payload())?);
    }
    Ok(frames)
}

/// Reassembles one client → server multipart message (`size=` total base64 length, `data=` pieces).
#[derive(Debug, Default)]
pub struct MultipartAssembler {
    declared: Option<i64>,
    base64: Vec<u8>,
}

impl MultipartAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one multipart frame. Returns the decoded TagField text once all pieces have arrived.
    pub fn push(&mut self, frame: &Frame) -> Result<Option<Vec<u8>>, MultipartError> {
        let r = TagFieldReader::new(&frame.payload);
        let size = r.get_int("size")?.ok_or(MultipartError::MissingField("size"))?;
        if size <= 0 {
            return Err(MultipartError::BadSize(size));
        }
        match self.declared {
            None => self.declared = Some(size),
            Some(first) if first != size => return Err(MultipartError::SizeChanged { first, now: size }),
            Some(_) => {}
        }
        let data = r.get_bytes("data")?.ok_or(MultipartError::MissingField("data"))?;
        self.base64.extend_from_slice(&data);
        let declared = size as usize;
        if self.base64.len() > declared {
            return Err(MultipartError::Overrun { declared, have: self.base64.len() });
        }
        if self.base64.len() < declared {
            return Ok(None);
        }
        let decoded = B64.decode(&self.base64).map_err(|e| MultipartError::Base64(e.to_string()))?;
        Ok(Some(decoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameDecoder;

    #[test]
    fn id_words() {
        assert_eq!(FeslId::reply(5), 0x8000_0005);
        assert_eq!(FeslId::request(1), 0xC000_0001);
        assert_eq!(FeslId::decode(0xF000_0003), FeslId { tid: 3, multipart: true });
        assert_eq!(FeslId::decode(0xC000_0001), FeslId { tid: 1, multipart: false });
        assert_eq!(FeslId::decode(FeslId::multipart_reply(9)), FeslId { tid: 9, multipart: true });
    }

    #[test]
    fn small_reply_is_one_plain_frame() {
        let mut t = TagFields::new();
        t.set_str("TXN", "Hello").unwrap();
        let frames = encode_reply(Kind::new(b"fsys"), 1, &t, 8096).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(&frames[0][4..8], &[0x80, 0, 0, 1]);
    }

    #[test]
    fn large_reply_splits_on_quads_with_decoded_size_first() {
        let mut t = TagFields::new();
        t.set_str("TXN", "GetStats").unwrap();
        for i in 0..200 {
            t.set_str(&format!("stats.{i}.key"), format!("value_{i}")).unwrap();
        }
        let fragment = 256;
        let frames = encode_reply(Kind::new(b"rank"), 4, &t, fragment).unwrap();
        assert!(frames.len() > 1);

        let mut dec = FrameDecoder::new(fragment + 0x80);
        let mut joined = Vec::new();
        let mut declared = None;
        for (i, bytes) in frames.iter().enumerate() {
            dec.feed(bytes);
            let f = dec.next_frame().unwrap().unwrap();
            assert_eq!(FeslId::decode(f.id), FeslId { tid: 4, multipart: true });
            let r = TagFieldReader::new(&f.payload);
            let has_size = r.get_int("decodedSize").unwrap();
            if i == 0 {
                declared = has_size;
            } else {
                assert_eq!(has_size, None);
            }
            let data = r.get_bytes("data").unwrap().unwrap();
            assert_eq!(data.len() % 4, 0, "client decoder rejects non-quad parts");
            if i + 1 < frames.len() {
                assert!(!data.contains(&b'='), "padding only in the last part");
            }
            joined.extend_from_slice(&data);
        }
        let decoded = B64.decode(&joined).unwrap();
        assert_eq!(declared, Some(decoded.len() as i64));
        assert_eq!(decoded, t.to_text());
    }

    #[test]
    fn assembler_reassembles_client_style_parts() {
        let text = b"TXN=UpdateStats\nu.[]=1\nu.0.v=xyz\n".to_vec();
        let encoded = B64.encode(&text);
        let mut asm = MultipartAssembler::new();
        let pieces: Vec<&[u8]> = encoded.as_bytes().chunks(7).collect();
        for (i, piece) in pieces.iter().enumerate() {
            let mut p = TagFields::new();
            p.set_int("size", encoded.len() as i64).unwrap();
            p.set_str("data", piece).unwrap();
            let f = Frame { kind: Kind::new(b"rank"), id: 0xF000_0002, payload: p.to_payload() };
            let out = asm.push(&f).unwrap();
            if i + 1 < pieces.len() {
                assert_eq!(out, None);
            } else {
                assert_eq!(out, Some(text.clone()));
            }
        }
    }

    #[test]
    fn assembler_rejects_overrun() {
        let mut p = TagFields::new();
        p.set_int("size", 4).unwrap();
        p.set_str("data", "QUJDRA==").unwrap();
        let f = Frame { kind: Kind::new(b"rank"), id: 0xF000_0002, payload: p.to_payload() };
        assert!(matches!(MultipartAssembler::new().push(&f), Err(MultipartError::Overrun { .. })));
    }

    #[test]
    fn tiny_fragment_size_is_an_error() {
        let mut t = TagFields::new();
        t.set_str("TXN", "x".repeat(100)).unwrap();
        assert_eq!(encode_reply(Kind::new(b"fsys"), 1, &t, 0x22), Err(MultipartError::FragmentTooSmall(0x22)));
    }
}
