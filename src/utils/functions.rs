use crate::utils::{
    consts::ANILIST_USER_BASE,
    structs::{OAuthCredential, OAuthSession, ViewerResponse},
};

use chrono::{DateTime, Utc};
use nanoid::nanoid;
use rocket::response::status::BadRequest;
use serde_json::json;
use sqlx::{Pool, Postgres};

pub async fn fetch_viewer_id(
    client: &reqwest::Client,
    access_token: &str,
) -> Result<i64, BadRequest<String>> {
    const USER_QUERY: &str = "
    query {
        Viewer {
            id
        }
    }
    ";

    let viewer_response = client
        .post(ANILIST_USER_BASE)
        .bearer_auth(access_token)
        .json(&json!({ "query": USER_QUERY }))
        .send()
        .await
        .map_err(|e| BadRequest(format!("Failed to fetch AniList viewer: {e}")))?
        .error_for_status()
        .map_err(|e| BadRequest(format!("AniList viewer request failed: {e}")))?;

    let viewer_response = viewer_response
        .json::<ViewerResponse>()
        .await
        .map_err(|e| BadRequest(format!("Failed to parse AniList viewer: {e}")))?;

    Ok(viewer_response.data.viewer.id)
}

/// Prototype-era token save; keyed on anilist_id only. Used by the existing /authorized
/// callback and will be replaced in ANNIE-129 when the full callback is rewritten.
pub async fn save_access_token(
    access_token: &str,
    anilist_id: i64,
    db: &Pool<Postgres>,
) -> Result<(), sqlx::Error> {
    info!("Saving access token ...");
    sqlx::query("UPDATE users SET access_token=$1 WHERE anilist_id=$2")
        .bind(access_token)
        .bind(anilist_id)
        .execute(db)
        .await
        .map(|_| ())
}

/// Upserts AniList OAuth credentials for the given Discord user. On conflict on
/// `discord_user_id`, updates all token fields and refreshes `token_updated_at`.
pub async fn upsert_oauth_credentials(
    discord_user_id: &str,
    anilist_id: i64,
    access_token: &str,
    refresh_token: Option<&str>,
    token_expires_at: Option<DateTime<Utc>>,
    db: &Pool<Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_credentials \
         (discord_user_id, anilist_id, access_token, refresh_token, token_expires_at, token_updated_at) \
         VALUES ($1, $2, $3, $4, $5, NOW()) \
         ON CONFLICT (discord_user_id) DO UPDATE SET \
             anilist_id = EXCLUDED.anilist_id, \
             access_token = EXCLUDED.access_token, \
             refresh_token = EXCLUDED.refresh_token, \
             token_expires_at = EXCLUDED.token_expires_at, \
             token_updated_at = NOW()",
    )
    .bind(discord_user_id)
    .bind(anilist_id)
    .bind(access_token)
    .bind(refresh_token)
    .bind(token_expires_at)
    .execute(db)
    .await
    .map(|_| ())
}

pub async fn fetch_credential_by_discord_user(
    discord_user_id: &str,
    db: &Pool<Postgres>,
) -> Result<Option<OAuthCredential>, sqlx::Error> {
    sqlx::query_as::<_, OAuthCredential>(
        "SELECT discord_user_id, anilist_id, access_token, refresh_token, \
         token_expires_at, token_updated_at, created_at \
         FROM oauth_credentials WHERE discord_user_id = $1",
    )
    .bind(discord_user_id)
    .fetch_optional(db)
    .await
}

pub async fn fetch_credential_by_anilist_id(
    anilist_id: i64,
    db: &Pool<Postgres>,
) -> Result<Option<OAuthCredential>, sqlx::Error> {
    sqlx::query_as::<_, OAuthCredential>(
        "SELECT discord_user_id, anilist_id, access_token, refresh_token, \
         token_expires_at, token_updated_at, created_at \
         FROM oauth_credentials WHERE anilist_id = $1",
    )
    .bind(anilist_id)
    .fetch_optional(db)
    .await
}

pub fn get_state_token() -> String {
    nanoid!(32)
}

/// Inserts a new OAuth session record. The session expires in 5 minutes.
pub async fn insert_oauth_session(
    state: &str,
    discord_user_id: &str,
    db: &Pool<Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_sessions (state, discord_user_id, expires_at) \
         VALUES ($1, $2, NOW() + INTERVAL '5 minutes')",
    )
    .bind(state)
    .bind(discord_user_id)
    .execute(db)
    .await
    .map(|_| ())
}

/// Outcome of attempting to consume an OAuth session.
#[derive(Debug)]
pub enum SessionConsumeError {
    /// No session with this state exists.
    NotFound,
    /// The session TTL has passed.
    Expired,
    /// The session was already consumed (replay attempt).
    AlreadyUsed,
    /// A database error occurred.
    Db(sqlx::Error),
}

/// Atomically marks the session as used and returns it, or explains why it failed.
///
/// On success the session record is consumed and cannot be replayed. On failure,
/// the reason is diagnosed via a secondary SELECT so callers can log it.
pub async fn consume_oauth_session(
    state_val: &str,
    db: &Pool<Postgres>,
) -> Result<OAuthSession, SessionConsumeError> {
    // Atomic consume: only succeeds if the session exists, is unused, and has not expired.
    let session = sqlx::query_as::<_, OAuthSession>(
        "UPDATE oauth_sessions \
         SET used_at = NOW() \
         WHERE state = $1 AND used_at IS NULL AND expires_at > NOW() \
         RETURNING state, discord_user_id, expires_at, used_at, created_at",
    )
    .bind(state_val)
    .fetch_optional(db)
    .await
    .map_err(SessionConsumeError::Db)?;

    if let Some(s) = session {
        return Ok(s);
    }

    // Diagnose why the consume failed for logging.
    #[derive(sqlx::FromRow)]
    struct Diag {
        used_at: Option<DateTime<Utc>>,
        expires_at: DateTime<Utc>,
    }

    let diag = sqlx::query_as::<_, Diag>(
        "SELECT used_at, expires_at FROM oauth_sessions WHERE state = $1",
    )
    .bind(state_val)
    .fetch_optional(db)
    .await
    .map_err(SessionConsumeError::Db)?;

    match diag {
        None => Err(SessionConsumeError::NotFound),
        Some(d) if d.used_at.is_some() => Err(SessionConsumeError::AlreadyUsed),
        Some(_) => Err(SessionConsumeError::Expired),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        consume_oauth_session, fetch_credential_by_anilist_id, fetch_credential_by_discord_user,
        insert_oauth_session, upsert_oauth_credentials, SessionConsumeError,
    };
    use chrono::{Duration, Utc};
    use sqlx::{Pool, Postgres};

    #[sqlx::test(migrations = "./migrations")]
    async fn upsert_inserts_new_credential(pool: Pool<Postgres>) {
        upsert_oauth_credentials(
            "111222333444555666",
            987654321,
            "access_tok",
            Some("refresh_tok"),
            Some(Utc::now() + Duration::hours(1)),
            &pool,
        )
        .await
        .expect("upsert should succeed");

        let cred = fetch_credential_by_discord_user("111222333444555666", &pool)
            .await
            .expect("fetch should not error")
            .expect("credential should exist");

        assert_eq!(cred.discord_user_id, "111222333444555666");
        assert_eq!(cred.anilist_id, 987654321);
        assert_eq!(cred.access_token, "access_tok");
        assert_eq!(cred.refresh_token.as_deref(), Some("refresh_tok"));
        assert!(cred.token_expires_at.is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn upsert_updates_existing_credential(pool: Pool<Postgres>) {
        upsert_oauth_credentials("user1", 111, "old_token", None, None, &pool)
            .await
            .expect("first upsert should succeed");

        upsert_oauth_credentials("user1", 111, "new_token", Some("new_refresh"), None, &pool)
            .await
            .expect("second upsert should succeed");

        let cred = fetch_credential_by_discord_user("user1", &pool)
            .await
            .expect("fetch should not error")
            .expect("credential should exist");

        assert_eq!(cred.access_token, "new_token");
        assert_eq!(cred.refresh_token.as_deref(), Some("new_refresh"));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fetch_by_discord_user_returns_none_when_absent(pool: Pool<Postgres>) {
        let result = fetch_credential_by_discord_user("nonexistent", &pool)
            .await
            .expect("fetch should not error");

        assert!(result.is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fetch_by_anilist_id_finds_correct_credential(pool: Pool<Postgres>) {
        upsert_oauth_credentials("user_a", 42, "tok_a", None, None, &pool)
            .await
            .expect("upsert should succeed");

        let cred = fetch_credential_by_anilist_id(42, &pool)
            .await
            .expect("fetch should not error")
            .expect("credential should exist");

        assert_eq!(cred.discord_user_id, "user_a");
        assert_eq!(cred.anilist_id, 42);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fetch_by_anilist_id_returns_none_when_absent(pool: Pool<Postgres>) {
        let result = fetch_credential_by_anilist_id(99999, &pool)
            .await
            .expect("fetch should not error");

        assert!(result.is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn consume_session_succeeds_for_valid_state(pool: Pool<Postgres>) {
        insert_oauth_session("state_abc", "123456789", &pool)
            .await
            .expect("insert should succeed");

        let session = consume_oauth_session("state_abc", &pool)
            .await
            .expect("consume should succeed");

        assert_eq!(session.discord_user_id, "123456789");
        assert!(session.used_at.is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn consume_session_fails_for_missing_state(pool: Pool<Postgres>) {
        let err = consume_oauth_session("no_such_state", &pool)
            .await
            .expect_err("consume should fail");

        assert!(matches!(err, SessionConsumeError::NotFound));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn consume_session_fails_on_replay(pool: Pool<Postgres>) {
        insert_oauth_session("replayable", "111", &pool)
            .await
            .expect("insert should succeed");

        consume_oauth_session("replayable", &pool)
            .await
            .expect("first consume should succeed");

        let err = consume_oauth_session("replayable", &pool)
            .await
            .expect_err("replay should fail");

        assert!(matches!(err, SessionConsumeError::AlreadyUsed));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn consume_session_fails_for_expired_state(pool: Pool<Postgres>) {
        // Insert a session that is already past its TTL.
        sqlx::query(
            "INSERT INTO oauth_sessions (state, discord_user_id, expires_at) \
             VALUES ($1, $2, NOW() - INTERVAL '1 minute')",
        )
        .bind("expired_state")
        .bind("222")
        .execute(&pool)
        .await
        .expect("direct insert should succeed");

        let err = consume_oauth_session("expired_state", &pool)
            .await
            .expect_err("expired session should fail");

        assert!(matches!(err, SessionConsumeError::Expired));
    }
}
