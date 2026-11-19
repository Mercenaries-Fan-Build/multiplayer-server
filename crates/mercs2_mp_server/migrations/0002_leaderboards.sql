-- Each player's best score per board (mp_api::rest, the leaderboard routes). Board names pass
-- mp_api::rules::check_board_name; scores are 0..=mp_api::rules::LEADERBOARD_SCORE_MAX.
CREATE TABLE leaderboard_scores (
    board      TEXT    NOT NULL,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    score      INTEGER NOT NULL CHECK (score BETWEEN 0 AND 1000000000),
    -- When the player first reached this score: an equal or lower push leaves the row unchanged.
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (board, user_id)
);
-- Board order: score descending, then who reached it first, then user id.
CREATE INDEX leaderboard_scores_order ON leaderboard_scores (board, score DESC, updated_at, user_id);

-- Accounts left out of every leaderboard list and rank, whose pushes are refused. Their score rows are kept.
CREATE TABLE leaderboard_bans (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    reason     TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);
