# OAuth data contract

This document describes the shared data contract between this
auth-service and the [`annie-mei`](https://github.com/annie-mei/annie-mei)
Discord bot so future changes have an explicit reference to check
against. Any change to the field names, types, or ID representation
listed here must be coordinated in **both** repos.

The bot mirrors this document at
[`annie-mei/docs/oauth-contract.md`](https://github.com/annie-mei/annie-mei/blob/main/docs/oauth-contract.md).

## Overview

```diagram
╭───────────╮  /register   ╭───────────╮  callback   ╭──────────────╮
│ Discord   │─────────────▶│ Bot       │────────────▶│ AniList      │
│ user      │              │ (annie-   │             │ OAuth        │
╰───────────╯              │  mei)     │             ╰──────┬───────╯
                           ╰────┬──────╯                    │
                                │ build_oauth_start_url     │ /oauth/anilist/callback
                                ▼                           ▼
                       ╭─────────────────╮        ╭──────────────────╮
                       │ Auth-service    │◀───────│ Auth-service     │
                       │ /oauth/anilist  │        │ /oauth/anilist   │
                       │   /start        │        │   /callback      │
                       ╰────────┬────────╯        ╰────────┬─────────╯
                                │ writes oauth_sessions    │ writes oauth_credentials
                                ▼                          ▼
                       ╭──────────────────────────────────────────╮
                       │              Postgres (shared)           │
                       │  oauth_sessions      oauth_credentials   │
                       ╰──────────────────────────────────────────╯
                                                ▲
                                                │ reads (whoami, guild overlay)
                                                │ deletes (unregister)
                                          Annie Mei bot
```

The auth-service owns both `oauth_credentials` and `oauth_sessions`.
The bot reads/deletes those rows directly via raw SQL using the same
shared Postgres database — it has no Diesel-managed tables of its own.

## Tables

### `oauth_credentials`

Source of truth for **linked** AniList accounts. Migrations live in
[`migrations/20260328000001_create_oauth_credentials.up.sql`](../migrations/20260328000001_create_oauth_credentials.up.sql)
and
[`migrations/20260401000003_add_oauth_credential_relink_fields.up.sql`](../migrations/20260401000003_add_oauth_credential_relink_fields.up.sql).

| Column                | Type            | Notes                                                                           |
| --------------------- | --------------- | ------------------------------------------------------------------------------- |
| `discord_user_id`     | `TEXT` (PK)     | Raw Discord snowflake **as a string** (matches the bot's `user.id.get().to_string()`). |
| `anilist_id`          | `BIGINT`        | AniList user ID. Unique across the table.                                       |
| `access_token`        | `TEXT`          | AniList OAuth access token.                                                     |
| `refresh_token`       | `TEXT NULL`     | AniList OAuth refresh token, when issued.                                       |
| `token_expires_at`    | `TIMESTAMPTZ NULL` | Token expiry, when AniList provides one.                                        |
| `token_updated_at`    | `TIMESTAMPTZ`   | Last token write time.                                                          |
| `created_at`          | `TIMESTAMPTZ`   | Initial link time.                                                              |
| `relink_required_at`  | `TIMESTAMPTZ NULL` | Set when this service decides the user must re-run `/register`.                 |
| `relink_reason`       | `TEXT NULL`     | Free-text reason that pairs with `relink_required_at`.                          |

**Auth-service writes:** `upsert_oauth_credentials` from
[`src/utils/functions.rs`](../src/utils/functions.rs), called from
[`src/routes/authorized.rs`](../src/routes/authorized.rs) on a
successful AniList token exchange.

**Bot reads:** `OAuthCredential::get_by_discord_id` (used by
`/whoami`) and `OAuthCredential::get_by_discord_ids` (used by the
per-guild MediaList overlay) in
`annie-mei/src/models/db/oauth_credential.rs`.

**Bot deletes:** `/unregister` deletes by `discord_user_id` in the
same transaction as `oauth_sessions`
(`annie-mei/src/commands/unregister.rs`).

### `oauth_sessions`

Short-lived state for in-flight OAuth flows. Migration:
[`migrations/20260328000002_create_oauth_sessions.up.sql`](../migrations/20260328000002_create_oauth_sessions.up.sql).

| Column            | Type           | Notes                                                                       |
| ----------------- | -------------- | --------------------------------------------------------------------------- |
| `state`           | `TEXT` (PK)    | Opaque per-flow state token issued by this service.                         |
| `discord_user_id` | `TEXT`         | Raw Discord snowflake string, mirroring `oauth_credentials.discord_user_id`. |
| `expires_at`      | `TIMESTAMPTZ`  | When the session token stops being valid.                                   |
| `used_at`         | `TIMESTAMPTZ NULL` | When the session was redeemed (replay protection).                          |
| `created_at`      | `TIMESTAMPTZ`  | Initial creation time.                                                      |

**Auth-service writes:** `/oauth/anilist/start` inserts the row before
redirecting the user to AniList; `/oauth/anilist/callback` marks
`used_at` to enforce single-use.

**Bot deletes:** `/unregister` includes
`DELETE FROM oauth_sessions WHERE discord_user_id = $1` in the same
transaction so half-finished flows do not linger after a user unlinks.

## OAuth context payload

The bot's `/register` command builds an opaque `ctx` query parameter
that this service consumes at `/oauth/anilist/start`. It is a
base64-url-encoded JSON payload signed with HMAC-SHA256 using the
shared `OAUTH_CONTEXT_SIGNING_SECRET`. Bot-side construction lives in
[`annie-mei/src/utils/oauth/mod.rs`](https://github.com/annie-mei/annie-mei/blob/main/src/utils/oauth/mod.rs).

| Field             | Type     | Notes                                                                                                          |
| ----------------- | -------- | -------------------------------------------------------------------------------------------------------------- |
| `v`               | `u8`     | Schema version. Currently `1`. Bump in both repos when fields change.                                          |
| `discord_user_id` | `string` | Raw Discord snowflake string.                                                                                  |
| `guild_id`        | `string` | Optional. Set when the `/register` interaction came from a guild.                                              |
| `interaction_id`  | `string` | Discord interaction ID for traceability.                                                                       |
| `nonce`           | `string` | 16-byte URL-safe base64 nonce.                                                                                 |
| `iat`             | `i64`    | Issued-at unix seconds.                                                                                        |
| `exp`             | `i64`    | Expiry unix seconds. Default TTL is `OAUTH_CONTEXT_TTL_SECONDS` (300s).                                        |

The signature segment is appended after `.` to form
`<payload_b64>.<sig_b64>`, identical on both sides.

## Coordinated change checklist

Make the matching change in both repos in the same release window if
you touch any of the following:

- A column on `oauth_credentials` or `oauth_sessions` (rename, type
  change, deletion, or new NOT NULL column).
- The `discord_user_id` representation (it must stay the raw Discord
  snowflake stringified via `user.id.get().to_string()` so bot
  cleanup queries continue to match auth-service writes).
- Any field on the OAuth context payload, or the `v` version constant.
- The `OAUTH_CONTEXT_SIGNING_SECRET` value or signing algorithm.

When making one of those changes:

1. Land the schema migration in this repo first.
2. Update the bot model / SQL in `annie-mei`.
3. Update both copies of `docs/oauth-contract.md`.
4. Coordinate the deploy so the auth-service migration runs before
   bot binaries that depend on the new shape are released.

## Privacy

`oauth_credentials.discord_user_id` and `oauth_sessions.discord_user_id`
intentionally store the raw Discord snowflake so that `/register`,
`/whoami`, and `/unregister` can all match on the same value. **Logs,
spans, and Sentry telemetry must not include the raw snowflake.** Use
`utils::observability::identifier_fingerprint` (this service) or
`crate::utils::privacy::hash_user_id` (bot) to emit a salted hash
instead. Both helpers use the shared `USERID_HASH_SALT` environment
variable so fingerprints correlate across repos; keep that variable
listed in the [README environment variables](../README.md#environment-variables).

The `ctx` query parameter on `/oauth/anilist/start` is base64url-encoded
JSON plus a signature, not encrypted data. It contains raw
`discord_user_id`, `guild_id`, and `interaction_id` values, so request
URL capture can leak those identifiers even when application logs use
fingerprints. Strip or redact the full `ctx` value from HTTP access logs,
Sentry transactions, request breadcrumbs, distributed tracing spans, and
any reverse-proxy logs before those observability records leave the
service.

`oauth_credentials.access_token` and `oauth_credentials.refresh_token`
are bearer credentials that grant full access to the linked AniList
account. **They must never appear in logs, spans, breadcrumbs, error
payloads, Sentry events, or any other observability sink — not in
plain text and not as a fingerprint.** When propagating an
`oauth_credentials` row through code that might be serialised by an
error handler or panic hook, redact both fields first or move them
behind a wrapper type whose `Debug`/`Display` impls do not expose the
secret. The same rule applies to AniList's response bodies for
`/oauth/anilist/callback`: never log the raw token-exchange response
body and never include `Authorization: Bearer …` headers in logged
HTTP requests.
