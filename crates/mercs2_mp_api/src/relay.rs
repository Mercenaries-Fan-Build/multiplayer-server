//! Datagram format carried inside each client's DTLS 1.2 association with the relay.
//!
//! ```text
//! HELLO  0x01 | token_len u8 | token bytes            client → relay, first datagram; binds the association
//! DATA   0x02 | slot u8 | channel u8 | payload        both directions; slot = the OTHER party
//! KEEP   0x03                                         client → relay; keeps a quiet association alive
//! ```
//!
//! From client to relay, `slot` names the destination peer; from relay to client it names the source peer.
//! `payload` is the game's datagram, forwarded unmodified (ProtoTunnel payloads are RC4-encrypted end to end
//! with the game's EKEY and carry the sender's clientId — `docs/reverse_engineer/multiplayer_rewrite_re.md` §6).

use thiserror::Error;

const TAG_HELLO: u8 = 0x01;
const TAG_DATA: u8 = 0x02;
const TAG_KEEPALIVE: u8 = 0x03;

/// Which game socket a datagram belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Channel {
    /// DirtySock ProtoTunnel (gameplay), UDP 10000 in the game.
    Tunnel,
    /// GameSpy Voice, UDP 55123 in the game.
    Voice,
}

impl Channel {
    fn to_byte(self) -> u8 {
        match self {
            Channel::Tunnel => 0,
            Channel::Voice => 1,
        }
    }

    fn from_byte(b: u8) -> Result<Self, RelayWireError> {
        match b {
            0 => Ok(Channel::Tunnel),
            1 => Ok(Channel::Voice),
            other => Err(RelayWireError::UnknownChannel(other)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Datagram<'a> {
    Hello { token: &'a [u8] },
    Data { slot: u8, channel: Channel, payload: &'a [u8] },
    /// Sent by a bound client while it has nothing else to send, so the relay's idle timeout
    /// ([`crate::ws::RelayAssignment::idle_timeout_secs`]) only ends associations whose client is gone.
    Keepalive,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RelayWireError {
    #[error("empty datagram")]
    Empty,
    #[error("unknown datagram tag 0x{0:02x}")]
    UnknownTag(u8),
    #[error("unknown channel {0}")]
    UnknownChannel(u8),
    #[error("truncated {0} datagram")]
    Truncated(&'static str),
    #[error("{0} datagram carries bytes after its fixed length")]
    Trailing(&'static str),
    #[error("token of {0} bytes exceeds 255")]
    TokenTooLong(usize),
}

impl<'a> Datagram<'a> {
    pub fn encode(&self) -> Result<Vec<u8>, RelayWireError> {
        match self {
            Datagram::Hello { token } => {
                let len = u8::try_from(token.len()).map_err(|_| RelayWireError::TokenTooLong(token.len()))?;
                let mut out = Vec::with_capacity(2 + token.len());
                out.extend_from_slice(&[TAG_HELLO, len]);
                out.extend_from_slice(token);
                Ok(out)
            }
            Datagram::Data { slot, channel, payload } => {
                let mut out = Vec::with_capacity(3 + payload.len());
                out.extend_from_slice(&[TAG_DATA, *slot, channel.to_byte()]);
                out.extend_from_slice(payload);
                Ok(out)
            }
            Datagram::Keepalive => Ok(vec![TAG_KEEPALIVE]),
        }
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, RelayWireError> {
        match bytes.first() {
            None => Err(RelayWireError::Empty),
            Some(&TAG_HELLO) => {
                let len = *bytes.get(1).ok_or(RelayWireError::Truncated("hello"))? as usize;
                let token = bytes.get(2..2 + len).ok_or(RelayWireError::Truncated("hello"))?;
                if bytes.len() != 2 + len {
                    return Err(RelayWireError::Truncated("hello"));
                }
                Ok(Datagram::Hello { token })
            }
            Some(&TAG_DATA) => {
                if bytes.len() < 3 {
                    return Err(RelayWireError::Truncated("data"));
                }
                Ok(Datagram::Data { slot: bytes[1], channel: Channel::from_byte(bytes[2])?, payload: &bytes[3..] })
            }
            Some(&TAG_KEEPALIVE) => {
                if bytes.len() != 1 {
                    return Err(RelayWireError::Trailing("keepalive"));
                }
                Ok(Datagram::Keepalive)
            }
            Some(&other) => Err(RelayWireError::UnknownTag(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for d in [
            Datagram::Hello { token: b"abc123" },
            Datagram::Data { slot: 1, channel: Channel::Tunnel, payload: b"\x00\x10xyz" },
            Datagram::Data { slot: 0, channel: Channel::Voice, payload: b"" },
            Datagram::Keepalive,
        ] {
            let bytes = d.encode().unwrap();
            assert_eq!(Datagram::decode(&bytes).unwrap(), d);
        }
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(Datagram::decode(b""), Err(RelayWireError::Empty));
        assert_eq!(Datagram::decode(b"\x09"), Err(RelayWireError::UnknownTag(9)));
        assert_eq!(Datagram::decode(b"\x01\x05ab"), Err(RelayWireError::Truncated("hello")));
        assert_eq!(Datagram::decode(b"\x02\x00\x07x"), Err(RelayWireError::UnknownChannel(7)));
        assert_eq!(Datagram::decode(b"\x02\x00"), Err(RelayWireError::Truncated("data")));
        assert_eq!(Datagram::decode(b"\x03\x00"), Err(RelayWireError::Trailing("keepalive")));
        assert_eq!(Datagram::Keepalive.encode().unwrap(), vec![0x03]);
    }
}
