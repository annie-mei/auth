# auth

Auth server for AniList OAuth for Annie Mei. It also owns the HTTP health and readiness endpoints for the Annie Mei stack.

## Local development

1. Copy `.env.example` to `.env`.
2. Fill in the AniList OAuth credentials, Postgres connection string, and a Rocket `ROCKET_SECRET_KEY`.
3. Start the service with `cargo run`.
4. Verify liveness with `curl http://127.0.0.1:8000/healthz` and readiness with `curl http://127.0.0.1:8000/readyz`.

`SENTRY_DSN` is optional in local development. If it is unset, the service will start without Sentry.

## Amp orbs

`.agents/setup` installs the toolchain pinned in `rust-toolchain.toml` (including
Clippy and rustfmt), fetches locked Cargo dependencies, and precompiles the test
suite for the project snapshot. Warm setup reuses installed packages and Cargo's
build cache. The first uncached setup takes longer while Rust and the crate graph
compile.

Setup also initializes a disposable PostgreSQL 15 cluster. `.amp/services.yaml`
runs it under Amp supervision, and `.agents/resume` ensures it is ready after
activation or wake. It listens only on loopback port 55432, has no portal, and uses
trust authentication and reduced durability for local tests only. CI uses
PostgreSQL 17; the orb uses Debian 12's packaged version.

New login shells inside this checkout have Cargo on `PATH` and default
`DATABASE_URL` to the local cluster, whose role can create SQLx test databases.
An existing `DATABASE_URL` is preserved; use only a disposable database when
running tests. No live credentials are needed for the test suite. To run the
OAuth server, follow the local-development instructions above and supply real
AniList credentials and valid signing keys separately; setup does not copy or
generate application secrets.

To repeat preparation or repair the database in an orb:

```sh
.agents/setup
.agents/resume
cargo test --locked
```

## Environment variables

- `ANILIST_CLIENT_ID`
- `ANILIST_CLIENT_SECRET`
- `ANILIST_REDIRECT_URI`
- `OAUTH_CONTEXT_SIGNING_SECRET`
- `OAUTH_CONTEXT_TTL_SECONDS` (optional, defaults to `300`)
- `OAUTH_STATE_TTL_SECONDS` (optional, defaults to `300`)
- `USERID_HASH_SALT`
- `DATABASE_URL`
- `ROCKET_SECRET_KEY`
- `SENTRY_DSN` (optional)

## Documentation

- [OAuth data contract](docs/oauth-contract.md) — shared schema and payload contract with the [`annie-mei`](https://github.com/annie-mei/annie-mei) bot repo
- [Database schema ownership](docs/database-schemas.md) — shared Postgres schemas, migration isolation, grants, and deployment order

## Validation

- `cargo fmt --check`
- `cargo check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test`
