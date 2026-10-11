//! Theater (and Messenger) id word and transaction id.
//!
//! Theater uses the same 12-byte frame and TagField encoder as FESL (client codec vtable `0xb5ec94`), but:
//!
//! * the client sends its requests with id `0x40000000` (other sends use 0) — there is no tid in the header
//!   (`0x970600`);
//! * when reading a server frame the client treats the **id word as the error code**: 0 means success
//!   (`0x9705f0`);
//! * the transaction id travels as the TagField key `TID`, appended last by the client (`0x976750` →
//!   `FUN_00975800`) and read back from `TID` in replies (`0x9705c0`). Messenger uses `ID` instead
//!   (vtable `0xb5ec68`);
//! * there is no multipart path — Theater's isChunked (`0x96db90`) always returns false. The client's
//!   Theater/Messenger receive buffer is `0x1fa0 + 0x80` bytes, so a frame larger than [`MAX_FRAME`] is
//!   dropped by the client.

use crate::frame::{self, FrameError, Kind};
use crate::tagfield::{TagFieldError, TagFieldReader, TagFields};

/// Largest Theater/Messenger frame the client accepts (`0x1fa0` buffer + `0x80`).
pub const MAX_FRAME: usize = 0x1fa0 + 0x80;

/// The id word the client puts on its requests.
pub const CLIENT_REQUEST_ID: u32 = 0x4000_0000;

/// The id word of a successful server reply or push.
pub const OK: u32 = 0;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TheaterError {
    #[error("Theater frame of {len} bytes exceeds the client's {MAX_FRAME}-byte receive buffer")]
    TooLarge { len: usize },
    #[error(transparent)]
    TagField(#[from] TagFieldError),
    #[error(transparent)]
    Frame(#[from] FrameError),
}

/// Encode a Theater reply or push. `error_code` is 0 on success. When replying to a request, set `tid` to
/// the request's `TID`; it is written last, as the client does.
pub fn encode(kind: Kind, error_code: u32, fields: &TagFields, tid: Option<i64>) -> Result<Vec<u8>, TheaterError> {
    let mut fields = fields.clone();
    if let Some(tid) = tid {
        fields.set_int("TID", tid)?;
    }
    let bytes = frame::encode(kind, error_code, &fields.to_payload())?;
    if bytes.len() > MAX_FRAME {
        return Err(TheaterError::TooLarge { len: bytes.len() });
    }
    Ok(bytes)
}

/// The `TID` of a received Theater request, if it carries one.
pub fn request_tid(payload: &[u8]) -> Result<Option<i64>, TagFieldError> {
    TagFieldReader::new(payload).get_int("TID")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameDecoder;

    #[test]
    fn reply_echoes_tid_last_and_uses_error_code_as_id() {
        let mut t = TagFields::new();
        t.set_str("NAME", "host one").unwrap();
        let bytes = encode(Kind::new(b"CGAM"), OK, &t, Some(3)).unwrap();
        let mut dec = FrameDecoder::new(MAX_FRAME);
        dec.feed(&bytes);
        let f = dec.next_frame().unwrap().unwrap();
        assert_eq!(f.id, 0);
        assert_eq!(f.payload, b"NAME=\"host one\"\nTID=3\n\0".to_vec());
        assert_eq!(request_tid(&f.payload).unwrap(), Some(3));
    }

    #[test]
    fn client_conn_request_shape_parses() {
        // Shape of the client's CONN builder FUN_0097adb0.
        let payload = b"PROT=2\nPROD=mercs2-pc\nVERS=1.0\nLOCALE=en_US\nSDKVERSION=4.3\nTID=1\n\0";
        assert_eq!(request_tid(payload).unwrap(), Some(1));
        assert_eq!(TagFieldReader::new(payload).get_int("PROT").unwrap(), Some(2));
    }

    #[test]
    fn oversize_theater_frame_is_refused() {
        let mut t = TagFields::new();
        t.set_str("X", "a".repeat(MAX_FRAME)).unwrap();
        assert!(matches!(encode(Kind::new(b"GDAT"), OK, &t, None), Err(TheaterError::TooLarge { .. })));
    }
}
