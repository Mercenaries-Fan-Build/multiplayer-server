//! Small shared helpers: CSPRNG output (OpenSSL `RAND_bytes`), hex, time.

use std::time::{SystemTime, UNIX_EPOCH};

use openssl::error::ErrorStack;

pub fn random_bytes(n: usize) -> Result<Vec<u8>, ErrorStack> {
    let mut buf = vec![0u8; n];
    openssl::rand::rand_bytes(&mut buf)?;
    Ok(buf)
}

const ALNUM: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// `len` characters drawn uniformly from ASCII letters and digits (rejection sampling, no modulo bias).
pub fn random_alnum(len: usize) -> Result<String, ErrorStack> {
    // 248 = 4 * 62: bytes below it map uniformly onto the alphabet.
    const LIMIT: u8 = 248;
    let mut out = String::with_capacity(len);
    while out.len() < len {
        for b in random_bytes(len * 2)? {
            if b < LIMIT {
                out.push(ALNUM[(b % 62) as usize] as char);
                if out.len() == len {
                    break;
                }
            }
        }
    }
    Ok(out)
}

/// A random RFC 4122 version-4 UUID string (36 characters).
pub fn random_uuid() -> Result<String, ErrorStack> {
    let mut b = random_bytes(16)?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    Ok(format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]))
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    openssl::sha::sha256(data)
}

/// Unix seconds now. The system clock being before 1970 is not a state this server can run in.
pub fn now_unix() -> i64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock is set before 1970-01-01");
    i64::try_from(since.as_secs()).expect("unix time exceeds i64")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alnum_has_exact_length_and_alphabet() {
        for len in [1, 16, 64] {
            let s = random_alnum(len).unwrap();
            assert_eq!(s.len(), len);
            assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn uuid_shape() {
        let u = random_uuid().unwrap();
        assert_eq!(u.len(), 36);
        assert_eq!(u.as_bytes()[14], b'4');
        assert_eq!(u.matches('-').count(), 4);
    }

    #[test]
    fn hex_encodes() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }
}
