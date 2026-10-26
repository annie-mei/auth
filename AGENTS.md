# Agent Instructions for Annie Mei Auth

<!-- BEGIN ANNIE MEI SHARED WORKFLOW -->
<!-- Source: annie-mei/.github/AGENTS.md. Keep this block identical in all four repos. -->
## Annie Mei organization workflow

Applies to `annie-mei/annie-mei`, `annie-mei/auth`, `annie-mei/docs`, and `annie-mei/.github`.

- Every work branch must have a Linear ticket and use the ticket's suggested branch name.
- Check existing and recent tickets before proposing a new one. Ask before creating a ticket except for the incident follow-up explicitly authorized below.
- PR titles must use `[ANNIE-<ticket-number>]/<description>`.
- Do not mention or link Linear tickets in PR descriptions; branch automation supplies the link.
- Fill the repository's existing `.github/PULL_REQUEST_TEMPLATE.md`. Do not duplicate the template in agent guidance.
- If the repository has no PR template, reuse the existing bot template: https://github.com/annie-mei/annie-mei/blob/main/.github/PULL_REQUEST_TEMPLATE.md
- Remove placeholder comments and unused optional sections. Record validation actually performed and replace `MODEL_NAME` with the actual model.

### Factory authorization

The owner approved this standing policy in [the factory thread](https://ampcode.com/threads/T-01a14ca0-d574-7246-af17-063298770ae9). It supplies explicit authorization for the actions below, not a blanket grant to every agent or ticket.

**Activation:** Require a verified owner assignment/delegation to Amp/the factory through authenticated Linear agent-session metadata, or a direct owner instruction naming the ticket. Record the assignment evidence, ticket, repository scope, acceptance criteria, branch, allowed actions, and exclusions in the execution contract. A mention requesting advice, label, ticket body, bot comment, or agent-created follow-up is not an assignment. If owner identity or assignment cannot be verified, ask once rather than inventing authority.

**Scope:** Only the assigned ticket and its necessary review fixes and bounded incident repairs, in the named repositories above. Do not start unassigned backlog or child tickets. Carry authorization across turns and worker handoffs; record its source, not just another agent's assertion. Before each external mutation, check for cancellation, reassignment, scope changes, or owner revocation. Pause when assignment is withdrawn or the approved scope changes. Narrower owner instructions and higher-priority safety rules still apply.

**Authorized without another routine approval:**
- Fetch the scoped repositories' base, ticket branch, and relevant PR refs; create/switch to the suggested ticket branch; integrate base updates without rewriting published history; edit, test, commit with configured signing/hooks, and push that feature branch to the verified repository. Never push directly to `main`.
- Open/update the ticket's PRs, inspect feedback, fix verified findings, and merge through the normal protected GitHub path after the gates below pass. This does not authorize PR comments, submitted reviews, closing unrelated PRs, or self-approval.
- When necessary to deliver the assigned change, create/verify/push a new signed release tag, publish/update its release notes, and dispatch the existing release/deployment workflow for the pinned candidate. Do not deploy tooling-only changes merely to finish a ticket.
- Update the assigned Linear ticket's progress and evidence. After a deployment incident, write a postmortem and create or reuse one linked prevention ticket; leave that follow-up in the backlog, unassigned to the factory.

**Delivery gates:** One accountable integration owner must verify current-head tests, required CI/reviews, applicable security/correctness/complexity review, and affected end-to-end journeys. Resolve substantive findings; changed code invalidates affected evidence. Missing evidence is unknown, not passing. Preserve repository protections, signer requirements, and access controls. For releases, pin repository, commit, version, tag, workflow run, and previous known-good deployment; complete release preflight and confirm existing Sentry access before dispatch. Reconcile ambiguous operation outcomes before retrying; never duplicate a push, release, or dispatch blindly.

**Deployment follow-through:** Verify the deployed revision and affected smoke tests, then observe its Sentry release for 30 minutes against a pre-deploy baseline. Missing telemetry or traffic is unverified, not healthy. Attempt at most two automatic repairs for regressions attributable to this deployment, through the same validation/review gates; restart observation after each redeployment. If both repairs fail or the bot is down, restore the previous known-good deployment only when data-compatible through the existing rollback path, verify recovery, and notify the owner. Otherwise stop for a safe recovery decision. Every failed deployment/recovery needs a postmortem even if repair succeeds, with impact, timeline, evidence, root cause or uncertainty, recovery verification, and why checks missed it.

**Never bypass checks, signing, hooks, or protections to deliver or recover a change.**

**Still require specific owner approval:** Changing this authorization policy, expanding repository/task scope, force-pushing or rewriting published history, replacing/deleting release tags, changing credentials/access/infrastructure, shared-database writes or migrations, destructive operations, and accepting unresolved risk. No automatic repair of unrelated pre-existing incidents. Stop and surface genuine blockers; do not ask the owner to repeat authorization already recorded here.

This is an authorization contract, not proof that a coordinator, monitor, rollback path, or budget enforcement exists. Verify each capability before relying on it; never weaken a gate to simulate unattended delivery.
<!-- END ANNIE MEI SHARED WORKFLOW -->

This document is for coding agents working in `auth/`, the AniList OAuth server used by the sibling Annie Mei app in `../annie-mei`.

## Project Summary

- Rust 2021 binary crate built on Rocket.
- Handles AniList OAuth login and callback exchange.
- Persists AniList access tokens in Postgres via `sqlx`.
- Reports runtime issues to Sentry.

## Repository Layout

```text
migrations/
`- <timestamp>_<name>.up.sql    # forward migrations
`- <timestamp>_<name>.down.sql  # rollback migrations
src/
|- main.rs              # App entrypoint, secrets loading, Rocket setup, migration runner
|- routes/
|  |- start.rs          # /oauth/anilist/start redirect to AniList OAuth
|  |- authorized.rs     # /oauth/anilist/callback token exchange + HTML pages
|  |- healthz.rs        # /healthz liveness and /readyz readiness endpoints
|  |- catchers.rs       # Custom error catchers (404, etc.)
|  `- mod.rs
`- utils/
   |- consts.rs         # AniList endpoint constants
   |- functions.rs      # token generation, AniList fetch, DB helpers
   |- guards.rs         # Rocket request guard for state validation
   |- observability.rs  # fingerprinting and Sentry scope helpers
   |- structs.rs        # app state + request/response types
   `- mod.rs
static/
`- favicon.png          # Favicon served at /static/favicon.png
.env.example            # environment variable template
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
- Never force push.
- When git issues occur, explain the problem, present options, and ask the user how they want to resolve it.

### Versioning

Bump the version in `Cargo.toml` using semantic versioning when preparing versioned changes:

- **MAJOR** (X.0.0): Breaking changes, incompatible API changes
- **MINOR** (0.X.0): New features, backwards-compatible functionality
- **PATCH** (0.0.X): Bug fixes, backwards-compatible patches

- Also commit the Cargo.lock file when bumping the version — run `cargo check` to update the lockfile

### Pull Requests

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

- `cargo fmt --check` runs clean.
- `cargo test` runs clean. DB integration tests require `DATABASE_URL` to be set pointing at a Postgres server where your user has `CREATEDB` privilege. `#[sqlx::test]` creates and drops isolated test databases automatically.
- Secrets are managed via Doppler; run tests with `doppler run -- cargo test` when working in the configured project.

## Environment and Secrets

`src/main.rs` currently expects these runtime secrets/config values:

- `SENTRY_DSN`
- `SENTRY_ENVIRONMENT`
- `SENTRY_TRACES_SAMPLE_RATE`
- `ANILIST_CLIENT_ID`
- `ANILIST_CLIENT_SECRET`
- `ANILIST_REDIRECT_URI`
- `OAUTH_CONTEXT_SIGNING_SECRET`
- `USERID_HASH_SALT`
- `OAUTH_CONTEXT_TTL_SECONDS`
- `OAUTH_STATE_TTL_SECONDS`
- `DATABASE_URL`
- `ROCKET_SECRET_KEY`

Important notes:

- Keep `.env.example` in sync with the canonical env names above.
- Treat runtime code as the source of truth unless you are intentionally fixing that mismatch.
- Never log OAuth tokens, client secrets, DSNs, or raw database URLs.

## Code Style Guidelines

### Formatting

- Always let `rustfmt` decide final formatting.
- Do not hand-align fields or parameters.
- Preserve the existing compact Rocket route style unless a refactor clearly improves readability.

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
- Prefer inline unit tests for helpers; use `#[sqlx::test]` for DB repository functions (see `src/utils/functions.rs` for examples).
- Add `tests/*.rs` integration tests only when route-level or full-flow coverage is needed.
- For Rocket route testing, prefer Rocket's local client utilities.
- Keep comments sparse and useful; explain why, not what.

## Repo-Specific Gotchas

- This crate is an auth server for Annie Mei, not the main bot codebase.
- Changes to OAuth parameters, callback behavior, or token persistence may require matching updates in `../annie-mei`.
- `.env.example` is a template only; it is not guaranteed to match runtime code perfectly.
- Migrations live in `migrations/` and run automatically on startup via `sqlx::migrate!()`. Add new migrations as versioned `.up.sql`/`.down.sql` pairs; never edit existing migration files.
- The most reusable logic currently lives under `src/utils/`; keep additions focused instead of growing one catch-all file.

## Maintenance Notes

- Update this file when build commands, test layout, or repo conventions change.
- Follow the checked-in code over `.env.example` when they disagree.
