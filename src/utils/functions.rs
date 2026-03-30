use crate::utils::{
    consts::ANILIST_TOKEN,
    structs::{OAuthCredential, OAuthSession, TokenErrorResponse, TokenResponse, ViewerResponse},
};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use nanoid::nanoid;
use rocket::response::status::BadRequest;
use serde_json::json;
use sha2::Sha256;
use sqlx::{Pool, Postgres};

#[derive(Debug)]
pub enum UpsertOAuthCredentialsError {
    AlreadyLinked,
    Db(sqlx::Error),
}

#[tracing::instrument(skip(client, access_token))]
pub async fn fetch_viewer_id(
    client: &reqwest::Client,
    user_endpoint: &str,
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
        .post(user_endpoint)
        .bearer_auth(access_token)
        .json(&json!({ "query": USER_QUERY }))
        .send()
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            BadRequest(format!("Failed to fetch AniList viewer: {e}"))
        })?
        .error_for_status()
        .map_err(|e| {
            sentry::capture_error(&e);
            BadRequest(format!("AniList viewer request failed: {e}"))
        })?;

    let viewer_response = viewer_response
        .json::<ViewerResponse>()
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            BadRequest(format!("Failed to parse AniList viewer: {e}"))
        })?;

    Ok(viewer_response.data.viewer.id)
}

pub async fn exchange_code_for_token(
    client: &reqwest::Client,
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
    code: &str,
) -> Result<TokenResponse, BadRequest<String>> {
    let response = client
        .post(token_endpoint)
        .json(&json!({
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code": code,
        }))
        .send()
        .await
        .map_err(|_| BadRequest("AniList token exchange request failed".to_string()))?;

    if response.status().is_success() {
        return response
            .json::<TokenResponse>()
            .await
            .map_err(|_| BadRequest("Failed to parse AniList token response".to_string()));
    }

    let status = response.status();
    let error_payload = response
        .json::<TokenErrorResponse>()
        .await
        .ok()
        .and_then(|payload| {
            payload
                .error
                .or(payload.error_description)
                .or(payload.message)
        })
        .unwrap_or_else(|| "unknown_error".to_string());

    let friendly_message = match error_payload.as_str() {
        "access_denied" => "Authorization was denied by AniList",
        "invalid_grant" => "Authorization code is invalid or expired",
        "invalid_client" => "AniList OAuth client configuration is invalid",
        "invalid_request" => "AniList token exchange request was invalid",
        _ => "AniList token exchange failed",
    };

    Err(BadRequest(format!(
        "{friendly_message} (status: {})",
        status.as_u16()
    )))
}

pub fn token_expires_at(expires_in_seconds: Option<i64>) -> Option<DateTime<Utc>> {
    expires_in_seconds
        .filter(|seconds| *seconds > 0)
        .map(|seconds| Utc::now() + chrono::Duration::seconds(seconds))
}

/// Upserts AniList OAuth credentials for the given Discord user. On conflict on
/// `discord_user_id`, updates all token fields and refreshes `token_updated_at`.
#[tracing::instrument(skip(access_token, refresh_token, db))]
pub async fn upsert_oauth_credentials(
    discord_user_id: &str,
    anilist_id: i64,
    access_token: &str,
    refresh_token: Option<&str>,
    token_expires_at: Option<DateTime<Utc>>,
    db: &Pool<Postgres>,
) -> Result<(), UpsertOAuthCredentialsError> {
    if let Some(existing) = fetch_credential_by_anilist_id(anilist_id, db)
        .await
        .map_err(UpsertOAuthCredentialsError::Db)?
        && existing.discord_user_id != discord_user_id
    {
        return Err(UpsertOAuthCredentialsError::AlreadyLinked);
    }

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
    .map_err(|error| {
        if is_anilist_id_conflict(&error) {
            UpsertOAuthCredentialsError::AlreadyLinked
        } else {
            UpsertOAuthCredentialsError::Db(error)
        }
    })
    .map(|_| ())
}

fn is_anilist_id_conflict(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Database(database_error) => {
            database_error.constraint() == Some("uq_oauth_credentials_anilist_id")
        }
        _ => false,
    }
}

#[tracing::instrument(skip(db))]
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

#[tracing::instrument(skip(db))]
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

/// Verifies that a login request was signed by the bot using the shared secret.
///
/// The bot constructs `HMAC-SHA256(discord_user_id + ":" + ts, BOT_AUTH_SECRET)`
/// and passes the hex-encoded result as `sig`. This function verifies that the
/// signature is valid and the timestamp is within a 2-minute window.
pub fn verify_bot_signature(discord_user_id: &str, ts: &str, sig: &str, secret: &str) -> bool {
    let timestamp: i64 = match ts.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };

    let now = Utc::now().timestamp();
    if timestamp > now || now.saturating_sub(timestamp) > 120 {
        return false;
    }

    let sig_bytes = match hex::decode(sig) {
        Ok(b) => b,
        Err(_) => return false,
    };

    type HmacSha256 = Hmac<Sha256>;
    let message = format!("{discord_user_id}:{ts}");
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(message.as_bytes());
    mac.verify_slice(&sig_bytes).is_ok()
}

/// Inserts a new OAuth session record. The session expires in 5 minutes.
#[tracing::instrument(skip(state, db))]
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
#[tracing::instrument(skip(state_val, db))]
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
    }

    let diag = sqlx::query_as::<_, Diag>("SELECT used_at FROM oauth_sessions WHERE state = $1")
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
        SessionConsumeError, UpsertOAuthCredentialsError, consume_oauth_session,
        fetch_credential_by_anilist_id, fetch_credential_by_discord_user, insert_oauth_session,
        token_expires_at, upsert_oauth_credentials, verify_bot_signature,
    };
    use chrono::{Duration, Utc};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use sqlx::{Pool, Postgres};

    fn make_sig(discord_user_id: &str, ts: i64, secret: &str) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let msg = format!("{discord_user_id}:{ts}");
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(msg.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn is_valid_state_token_accepts_correct_signature() {
        let secret = "test_secret";
        let ts = Utc::now().timestamp();
        let sig = make_sig("user1", ts, secret);
        assert!(verify_bot_signature("user1", &ts.to_string(), &sig, secret));
    }

    #[test]
    fn is_valid_state_token_rejects_tampered_user() {
        let secret = "test_secret";
        let ts = Utc::now().timestamp();
        let sig = make_sig("user1", ts, secret);
        assert!(!verify_bot_signature(
            "user2",
            &ts.to_string(),
            &sig,
            secret
        ));
    }

    #[test]
    fn is_valid_state_token_rejects_expired_timestamp() {
        let secret = "test_secret";
        let ts = Utc::now().timestamp() - 400;
        let sig = make_sig("user1", ts, secret);
        assert!(!verify_bot_signature(
            "user1",
            &ts.to_string(),
            &sig,
            secret
        ));
    }

    #[test]
    fn is_valid_state_token_rejects_bad_hex() {
        assert!(!verify_bot_signature("u", "0", "not_hex!!!", "s"));
    }

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

        pool.close().await;
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

        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fetch_by_discord_user_returns_none_when_absent(pool: Pool<Postgres>) {
        let result = fetch_credential_by_discord_user("nonexistent", &pool)
            .await
            .expect("fetch should not error");

        assert!(result.is_none());

        pool.close().await;
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

        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fetch_by_anilist_id_returns_none_when_absent(pool: Pool<Postgres>) {
        let result = fetch_credential_by_anilist_id(99999, &pool)
            .await
            .expect("fetch should not error");

        assert!(result.is_none());

        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn upsert_rejects_anilist_id_linked_to_another_discord_user(pool: Pool<Postgres>) {
        upsert_oauth_credentials("user_a", 42, "tok_a", None, None, &pool)
            .await
            .expect("initial upsert should succeed");

        let error = upsert_oauth_credentials("user_b", 42, "tok_b", None, None, &pool)
            .await
            .expect_err("conflicting upsert should fail");

        assert!(matches!(error, UpsertOAuthCredentialsError::AlreadyLinked));

        let credential = fetch_credential_by_anilist_id(42, &pool)
            .await
            .expect("fetch should not error")
            .expect("credential should still exist");

        assert_eq!(credential.discord_user_id, "user_a");
        assert_eq!(credential.access_token, "tok_a");

        pool.close().await;
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

    #[test]
    fn token_expiry_is_only_created_for_positive_values() {
        assert!(token_expires_at(None).is_none());
        assert!(token_expires_at(Some(0)).is_none());
        assert!(token_expires_at(Some(-10)).is_none());
        assert!(token_expires_at(Some(1)).is_some());
    }
}
