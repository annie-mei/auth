# Agent Instructions for Annie Mei Auth

This document is for coding agents working in `auth/`, the AniList OAuth server used by the sibling Annie Mei app in `../annie-mei`.

## Project Summary
- Rust 2021 binary crate built on Rocket.
- Handles AniList OAuth login and callback exchange.
- Persists AniList access tokens in Postgres via `sqlx`.
- Reports runtime issues to Sentry.

## Repository Layout
```text
src/
|- main.rs              # App entrypoint, secrets loading, Rocket setup
|- routes/
|  |- login.rs          # /login redirect to AniList OAuth
|  |- authorized.rs     # /authorized callback and token exchange
|  `- mod.rs
`- utils/
   |- consts.rs         # AniList endpoint constants
   |- functions.rs      # token generation, AniList fetch, DB helpers
   |- guards.rs         # Rocket request guard for state validation
   |- structs.rs        # app state + request/response types
   `- mod.rs
sample.Secrets.toml     # runtime secrets example
sample.Secrets.dev.toml # local development secrets example
sample.Rocket.toml      # Rocket config example
rustfmt.toml            # formatting config
```

## Conventions to Follow
### Code Style
- Run `cargo fmt` before finishing code changes.
- Run `cargo clippy` and fix warnings when the task touches behavior or structure.
- Prefer `?` over `unwrap()` for fallible paths.
- When implementing review findings, first verify the current code state and only apply changes that are actually missing.
- Preserve the existing pattern of thin Rocket handlers plus helper functions in `src/utils/`.

### Git Commits
- Use Conventional Commits and prefer `type(scope): summary`.
- Example: `fix(auth): handle AniList callback parse failures`.
- Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`.
- Make small, sensible commits; avoid batching unrelated changes.
- Squash WIP commits before opening a PR.

### Git Safety
- Never commit or push directly to `main`; use a feature branch.
- All branches should have a Linear ticket and use that ticket's branch naming.
- Do not create tickets automatically; check for an existing ticket first and ask before creating one.
- Never force push.
- When git issues occur, explain the problem, present options, and ask the user how they want to resolve it.

### Pull Requests
- PR titles should use `[ANNIE-<ticket-number>]/<description>`.
- PR descriptions should include `## Summary`, `## Type of Change`, `## Changes`, and `## Validation`.
- Include `### Notes` or `## References` when implementation details or operational context matter.
- In `## Validation`, list the exact commands run and any manual OAuth or local runtime checks.

## Build, Lint, and Test Commands
Use the repo root: `cd /Users/sekkensenzai/code/annie-mei/auth`

### Core commands
- Format: `cargo fmt`
- Format check: `cargo fmt --check`
- Typecheck: `cargo check`
- Build: `cargo build`
- Build release: `cargo build --release`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Run all tests: `cargo test`
- List tests: `cargo test -- --list`

### Running a single test
- By substring match: `cargo test state_token`
- By exact test path: `cargo test utils::functions::tests::is_valid_state_token -- --exact`
- Show test output: `cargo test state_token -- --nocapture`
- Future integration test file: `cargo test --test oauth_flow`

### Verification notes
- `cargo fmt --check` currently runs clean.
- `cargo test -- --list` currently fails because a transitive dependency needs `protoc`.
- `cargo test -- --list` also fails because `sqlx = 0.6` is missing a runtime feature in `Cargo.toml`.
- On macOS, installing protobuf is typically `brew install protobuf`.

## Environment and Secrets
`src/main.rs` currently expects these runtime secrets/config values:
- `SENTRY_DSN`
- `ANILIST_CLIENT_ID`
- `ANILIST_SECRET`
- `REDIRECT_URL`
- `DATABASE_URL`
- `SECRET_KEY`

Important notes:
- The checked-in sample secrets files currently use `SECRET`, but `src/main.rs` reads `SECRET_KEY`.
- Treat runtime code as the source of truth unless you are intentionally fixing that mismatch.
- Never commit real `Secrets.toml`, `Secrets.dev.toml`, or `Rocket.toml` files.
- Never log OAuth tokens, client secrets, DSNs, or raw database URLs.

## Code Style Guidelines
### Formatting
- Always let `rustfmt` decide final formatting.
- Do not hand-align fields or parameters.
- Preserve the existing compact Rocket route style unless a refactor clearly improves readability.
- Keep files ASCII unless the file already requires Unicode.

### Imports and naming
- Match nearby files rather than imposing a brand-new import order.
- Current modules usually keep `crate::...` imports first, then standard library or external imports.
- Separate import groups with a blank line when it improves readability.
- Prefer explicit imports over glob imports.
- Use `snake_case` for functions, modules, variables, and route handlers.
- Use `PascalCase` for structs and enums, and `SCREAMING_SNAKE_CASE` for constants.

### Types and structure
- Prefer concrete types over trait objects unless dynamic dispatch is required.
- Prefer borrowing (`&str`, `&State<T>`, `&Pool<Postgres>`) when ownership is not needed.
- Keep shared runtime dependencies inside app state (`MyState`) or a successor struct.
- Prefer typed `serde` structs over raw `serde_json::Value` when the upstream payload is stable.
- Keep Rocket handlers thin and move non-routing logic into helpers.
- Update `src/routes/mod.rs` or `src/utils/mod.rs` when adding modules.

### Async, HTTP, and database code
- Keep route handlers `async` and return Rocket-friendly types.
- Reuse the shared `reqwest::Client` stored in app state.
- Reuse the shared Postgres pool from app state.
- Centralize AniList URLs and similar constants in `src/utils/consts.rs`.
- Use bound parameters with `sqlx::query(...).bind(...)`; never interpolate untrusted input into SQL.
- Keep state validation inside request guards instead of duplicating it in handlers.

### Error handling
- Prefer `Result` returns and the `?` operator for fallible code.
- Use `map_err(...)` when converting low-level failures into Rocket response types.
- Avoid adding new `unwrap()` or `expect()` calls in network, DB, parsing, header, URL, or secret-loading paths.
- Treat existing `unwrap()` usage as legacy, not as the preferred style for new code.
- Return user-safe error messages from routes and keep richer detail in logs.
- When reading secrets, fail fast with explicit messages rather than silently defaulting.

### Logging, testing, and comments
- The current codebase uses Rocket logging macros such as `info!`; stay consistent unless you are intentionally migrating logging.
- Log high-level state transitions, not sensitive payloads.
- Keep Sentry initialization in startup code, not scattered across handlers.
- There are currently no checked-in unit tests or integration tests; prefer inline unit tests for helpers.
- Add `tests/*.rs` integration tests only when route-level or full-flow coverage is needed.
- For Rocket route testing, prefer Rocket's local client utilities.
- Keep comments sparse and useful; explain why, not what.

## Repo-Specific Gotchas
- This crate is an auth server for Annie Mei, not the main bot codebase.
- Changes to OAuth parameters, callback behavior, or token persistence may require matching updates in `../annie-mei`.
- The sample config files are examples only; they are not guaranteed to match runtime code perfectly.
- `Cargo.lock` is currently gitignored in this repo.
- There are no migrations checked into this repo, so schema changes must be coordinated carefully.
- The most reusable logic currently lives under `src/utils/`; keep additions focused instead of growing one catch-all file.

## Maintenance Notes
- Update this file when build commands, test layout, or repo conventions change.
- If you hit the known `protoc` or `sqlx` runtime blockers during verification, mention them in your handoff.
- Follow the checked-in code over sample config files when they disagree.
