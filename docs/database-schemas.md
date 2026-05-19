# Database schema ownership

The auth-service and Annie Mei bot share one Postgres database but own separate schemas so their SQLx migration histories do not conflict.

| Schema | Owner | Tables |
| --- | --- | --- |
| `annie_auth` | auth-service | `oauth_credentials`, `oauth_sessions` |
| `annie_mei` | Annie Mei bot | `user_settings`, `guild_settings` |

Runtime queries should use schema-qualified table names. Do not rely on `search_path` for application reads or writes.

## Auth-service migrations

Auth-service startup ensures the `annie_auth` schema exists, then runs SQLx migrations with the migration connection `search_path` set to `annie_auth,public`. SQLx therefore creates and reads `annie_auth._sqlx_migrations`.

Auth-service migrations define auth-owned tables directly in the `annie_auth` schema. They do not move legacy `public` tables or preserve old `public._sqlx_migrations` state. The ANNIE-189 deployment is a major-version schema reset: existing OAuth rows must be re-created by users running `/register` again after deploy.

For a clean cutover, remove old app-owned public tables and SQLx history before deploying the new auth-service:

```sql
DROP TABLE IF EXISTS public.oauth_sessions CASCADE;
DROP TABLE IF EXISTS public.oauth_credentials CASCADE;
DROP TABLE IF EXISTS public._sqlx_migrations CASCADE;

DROP TABLE IF EXISTS annie_auth.oauth_sessions CASCADE;
DROP TABLE IF EXISTS annie_auth.oauth_credentials CASCADE;
DROP TABLE IF EXISTS annie_auth._sqlx_migrations CASCADE;

CREATE SCHEMA IF NOT EXISTS annie_auth;
CREATE SCHEMA IF NOT EXISTS annie_mei;
```

After the reset, auth-service startup recreates `annie_auth.oauth_credentials`, `annie_auth.oauth_sessions`, and `annie_auth._sqlx_migrations` from the checked-in migrations.

## Annie Mei bot schema

The bot owns `annie_mei.user_settings` and `annie_mei.guild_settings`. Until the bot runs SQLx migrations at startup, create those tables manually during the cutover or run the bot migrations with the intended schema context.

```sql
CREATE SCHEMA IF NOT EXISTS annie_mei;

CREATE TABLE IF NOT EXISTS annie_mei.user_settings (
    discord_user_id TEXT NOT NULL,
    setting_key TEXT NOT NULL,
    setting_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (discord_user_id, setting_key)
);

CREATE TABLE IF NOT EXISTS annie_mei.guild_settings (
    guild_id TEXT NOT NULL,
    setting_key TEXT NOT NULL,
    setting_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (guild_id, setting_key)
);
```

## Permissions

The auth-service database role should own or fully manage objects in `annie_auth`.

The Annie Mei database role needs cross-schema access for account-link commands:

```sql
GRANT USAGE ON SCHEMA annie_auth TO annie_mei_bot;
GRANT SELECT, DELETE ON annie_auth.oauth_credentials TO annie_mei_bot;
GRANT SELECT, DELETE ON annie_auth.oauth_sessions TO annie_mei_bot;
```

The Annie Mei role also needs read/write access to its own schema:

```sql
GRANT USAGE ON SCHEMA annie_mei TO annie_mei_bot;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA annie_mei TO annie_mei_bot;
```

Use the real runtime role name for each environment. In local/Supabase development this may be `annie` instead of `annie_mei_bot`.

## Deployment order

1. Stop old auth-service and bot instances.
2. Back up the database if any data should be recoverable.
3. Run the destructive reset SQL above for legacy OAuth tables and SQLx history.
4. Deploy auth-service so startup creates fresh `annie_auth.*` tables and `annie_auth._sqlx_migrations`.
5. Create or migrate bot-owned `annie_mei.*` settings tables.
6. Grant cross-schema permissions for the runtime roles.
7. Deploy Annie Mei bot code that reads `annie_auth.*` and writes `annie_mei.*`.
8. Re-run `/register` for affected users because OAuth credentials were reset.

Avoid public compatibility views for this cutover. They can confuse schema checks and do not safely cover old write paths such as OAuth upserts.

## Rollback

This cutover is destructive for OAuth rows. Roll back application code by redeploying the prior versions and restoring a database backup if the old rows are needed.
