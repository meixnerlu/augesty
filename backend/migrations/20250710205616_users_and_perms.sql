-- Add migration script here
PRAGMA foreign_keys = ON;

-- 1: core users table
CREATE TABLE users (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    user_type TEXT NOT NULL CHECK(user_type IN ('user','serviceaccount'))
);

-- 2: Type 1 details (one‑to‑one)
CREATE TABLE user_pw_hash (
    user_id INTEGER PRIMARY KEY,
    pw_hash TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 3: Type 2 identifiers (one‑to‑many)
CREATE TABLE user_identifiers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    identifier TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, identifier)
);

-- 4: permissions (many‑to‑many via a join table style)
CREATE TABLE permissions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    subject    TEXT NOT NULL,
    permission TEXT NOT NULL CHECK(permission IN ('pull','push')),
    UNIQUE(subject, permission)
);

CREATE TABLE user_permissions (
    user_id       INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY(user_id, permission_id),
    FOREIGN KEY(user_id)       REFERENCES users(id)       ON DELETE CASCADE,
    FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);