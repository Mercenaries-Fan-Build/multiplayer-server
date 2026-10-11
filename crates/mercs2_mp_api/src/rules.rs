//! Field rules enforced by the server and pre-checked by the ASI.
//!
//! Lengths that come from the game client cite the parser buffer they must fit
//! (`docs/reverse_engineer/multiplayer_txn_catalogue.md`). The remaining rules are project policy and are
//! marked as such.

use crate::{ApiError, ErrorCode};

/// The Login reply parser copies `displayName` into a 31-character buffer (`0x988fe0`).
pub const USERNAME_MAX: usize = 31;
/// Policy: shortest accepted username.
pub const USERNAME_MIN: usize = 3;
/// Policy: password length bounds (argon2id input; the game's own field is a C string).
pub const PASSWORD_MIN: usize = 8;
pub const PASSWORD_MAX: usize = 128;
/// CGAM / EGEG parse `EKEY` into a 16-character buffer (`FUN_0097b9b0`, `FUN_00981490`).
pub const EKEY_LEN: usize = 16;
/// CGAM reply `SECRET` buffer is 127 characters (`FUN_0097b9b0`).
pub const SECRET_MAX: usize = 127;
/// CGAM reply `UGID` buffer is 36 characters (`FUN_0097b9b0`).
pub const UGID_MAX: usize = 36;
/// Policy: room keys are 6–32 characters from [`is_code_char`].
pub const ROOM_KEY_MIN: usize = 6;
pub const ROOM_KEY_MAX: usize = 32;

fn invalid(field: &str, rule: &str) -> ApiError {
    ApiError::new(ErrorCode::InvalidField, format!("{field}: {rule}"))
}

/// Policy: usernames are ASCII letters, digits, `_`, `-`, `.` — they appear in the game UI, Theater `NAME`
/// fields and server lists, and a restricted alphabet rules out look-alike impersonation.
pub fn check_username(name: &str) -> Result<(), ApiError> {
    let n = name.chars().count();
    if !(USERNAME_MIN..=USERNAME_MAX).contains(&n) {
        return Err(invalid("username", &format!("must be {USERNAME_MIN}-{USERNAME_MAX} characters")));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')) {
        return Err(invalid("username", "may contain only ASCII letters, digits, '_', '-' and '.'"));
    }
    Ok(())
}

pub fn check_password(password: &str) -> Result<(), ApiError> {
    let n = password.chars().count();
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&n) {
        return Err(invalid("password", &format!("must be {PASSWORD_MIN}-{PASSWORD_MAX} characters")));
    }
    Ok(())
}

pub fn is_code_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

/// Validates a room key ([`crate::ws::Privacy::room_key`]). Keys are compared exactly — case-sensitive, so
/// `Venezuela-42` and `venezuela-42` are different rooms — and are not unique among live games.
pub fn check_room_key(key: &str) -> Result<(), ApiError> {
    let n = key.chars().count();
    if !(ROOM_KEY_MIN..=ROOM_KEY_MAX).contains(&n) || !key.chars().all(is_code_char) {
        return Err(invalid("room_key", &format!("must be {ROOM_KEY_MIN}-{ROOM_KEY_MAX} ASCII letters, digits or '-'")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_limits_follow_client_buffer() {
        assert!(check_username(&"a".repeat(USERNAME_MAX)).is_ok());
        assert!(check_username(&"a".repeat(USERNAME_MAX + 1)).is_err());
        assert!(check_username("ab").is_err());
        assert!(check_username("has space").is_err());
        assert!(check_username("Mattias.N_2").is_ok());
    }

    #[test]
    fn password_and_code_limits() {
        assert!(check_password("short").is_err());
        assert!(check_password("long enough").is_ok());
        assert!(check_room_key("abc").is_err());
        assert!(check_room_key("venezuela-42").is_ok());
        assert!(check_room_key("no spaces!").is_err());
        assert!(check_room_key(&"a".repeat(ROOM_KEY_MAX)).is_ok());
        assert!(check_room_key(&"a".repeat(ROOM_KEY_MAX + 1)).is_err());
    }
}
