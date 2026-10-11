//! Wire codec for the Mercenaries 2 PC online protocol (EA Plasma: FESL + Theater + Messenger).
//!
//! Every rule here is mirrored from the game client's own encoder/decoder in the unpacked exe, not from
//! earlier emulators; each module cites the client functions it follows. Evidence write-up:
//! `docs/reverse_engineer/multiplayer_rewrite_re.md` in the parent repository.
//!
//! * [`frame`] — the 12-byte ProtoAries frame shared by all three services.
//! * [`tagfield`] — the `key=value` payload text.
//! * [`fesl`] — FESL id word (tid + flags) and multipart messages.
//! * [`theater`] — Theater id word (error code) and `TID`.

pub mod fesl;
pub mod frame;
pub mod tagfield;
pub mod theater;

pub use frame::{Frame, FrameDecoder, FrameError, Kind};
pub use tagfield::{TagFieldError, TagFieldReader, TagFields};
