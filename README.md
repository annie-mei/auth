# auth

Auth server for AniList OAuth for Annie Mei.

## Local development

1. Copy `.env.example` to `.env`.
2. Fill in the AniList OAuth credentials, Postgres connection string, and a Rocket `ROCKET_SECRET_KEY`.
3. Start the service with `cargo run`.

`SENTRY_DSN` is optional in local development. If it is unset, the service will start without Sentry.

## Environment variables

- `ANILIST_CLIENT_ID`
- `ANILIST_CLIENT_SECRET`
- `ANILIST_REDIRECT_URI`
- `OAUTH_CONTEXT_SIGNING_SECRET`
- `OAUTH_CONTEXT_TTL_SECONDS` (optional, defaults to `300`)
- `OAUTH_STATE_TTL_SECONDS` (optional, defaults to `300`)
- `DATABASE_URL`
- `ROCKET_SECRET_KEY`
- `SENTRY_DSN` (optional)

## Validation

- `cargo fmt --check`
- `cargo check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
