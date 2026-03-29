CREATE TABLE IF NOT EXISTS oauth_sessions (
    state           TEXT        PRIMARY KEY,
    discord_user_id TEXT        NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
