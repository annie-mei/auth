use crate::utils::{
    consts::ANILIST_USER_BASE,
    structs::{OAuthCredential, ViewerResponse},
};

use chrono::{DateTime, Utc};
use nanoid::nanoid;
use rocket::{http::CookieJar, response::status::BadRequest};
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

pub fn is_valid_state_token(jar: &CookieJar, state: &str) -> bool {
    let state_cookie = jar.get_private("state").or_else(|| {
        info!("State cookie not found from get_private");
        jar.get_pending("state")
    });

    if let Some(state_cookie) = state_cookie {
        if state_cookie.value() == state {
            jar.remove_private(("state", ""));
            return true;
        }

        info!("State token mismatch");
    } else {
        info!("State cookie not found");
    }

    false
}
