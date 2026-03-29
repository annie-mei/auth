CREATE TABLE IF NOT EXISTS oauth_credentials (
    discord_user_id    TEXT        PRIMARY KEY,
    anilist_id         BIGINT      NOT NULL,
    access_token       TEXT        NOT NULL,
    refresh_token      TEXT,
    token_expires_at   TIMESTAMPTZ,
    token_updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_oauth_credentials_anilist_id UNIQUE (anilist_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_credentials_anilist_id ON oauth_credentials (anilist_id);
