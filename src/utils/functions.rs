use crate::utils::{consts::ANILIST_USER_BASE, structs::ViewerResponse};

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
            return true;
        }

        info!("State token mismatch");
    } else {
        info!("State cookie not found");
    }

    false
}
