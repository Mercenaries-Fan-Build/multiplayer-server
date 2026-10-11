-- Accounts. Usernames are ASCII-only (mp_api::rules::check_username), so NOCASE gives exact
-- case-insensitive uniqueness.
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL
);

-- Only the sha256 of each bearer token is stored.
CREATE TABLE sessions (
    token_sha256  BLOB    PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    build_sha256  TEXT    NOT NULL,
    asi_version   TEXT    NOT NULL
);
CREATE INDEX sessions_expires_at ON sessions(expires_at);

-- Directional friend list (asso): user_id added friend_id. Mutual = both rows exist.
CREATE TABLE friends (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    friend_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, friend_id),
    CHECK (user_id <> friend_id)
);
CREATE INDEX friends_friend_id ON friends(friend_id);

-- rank stats, kept as the text the game sent.
CREATE TABLE stats (
    owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key        TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (owner_id, key)
);
