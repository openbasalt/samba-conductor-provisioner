-- One-time tokens: only the SHA-256 of the raw token (with a domain
-- separator) is stored, never the token itself, and never a password.
CREATE TABLE tokens (
    id            TEXT PRIMARY KEY,
    hash          BLOB NOT NULL UNIQUE,
    purpose       TEXT NOT NULL,
    sid           TEXT NOT NULL,
    guid          TEXT NOT NULL,
    sam           TEXT NOT NULL,
    pwd_last_set  INTEGER NOT NULL,
    was_disabled  INTEGER NOT NULL,
    issued_by     TEXT NOT NULL,
    reference     TEXT NOT NULL,
    issued_at     TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    state         TEXT NOT NULL,
    state_reason  TEXT NOT NULL DEFAULT '',
    password_set_at TEXT NOT NULL DEFAULT '',
    closed_at     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX tokens_sid ON tokens(sid, purpose, state);
CREATE INDEX tokens_state ON tokens(state, expires_at);

-- Hash-chained audit log, keyed with the state key.
CREATE TABLE audit (
    seq        INTEGER PRIMARY KEY,
    at         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    op         TEXT NOT NULL,
    target_sid TEXT NOT NULL,
    target_sam TEXT NOT NULL,
    token_id   TEXT NOT NULL,
    reference  TEXT NOT NULL,
    result     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
