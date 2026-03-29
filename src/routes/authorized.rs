use crate::utils::{
    consts::ANILIST_TOKEN,
    functions::{fetch_viewer_id, upsert_oauth_credentials},
    structs::{MyState, StateToken, TokenResponse},
};

use chrono::{Duration, Utc};
use rocket::{State, response::status::BadRequest};
use serde_json::json;

#[get("/authorized?<code>")]
pub async fn authorized(
    code: String,
    state_token: StateToken,
    state: &State<MyState>,
) -> Result<String, BadRequest<String>> {
    info!("State token validated; beginning token exchange");

    sentry::configure_scope(|scope| {
        scope.set_user(Some(sentry::User {
            id: Some(state_token.0.clone()),
            ..Default::default()
        }));
    });

    let response = state
        .client
        .post(ANILIST_TOKEN)
        .json(&json!({
            "grant_type": "authorization_code",
            "client_id": state.client_id.as_str(),
            "client_secret": state.client_secret.as_str(),
            "redirect_uri": state.redirect_uri.as_str(),
            "code": code,
        }))
        .send()
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            BadRequest(format!("AniList token exchange failed: {e}"))
        })?
        .error_for_status()
        .map_err(|e| {
            sentry::capture_error(&e);
            BadRequest(format!("AniList token exchange failed: {e}"))
        })?;

    let token_response = response.json::<TokenResponse>().await.map_err(|e| {
        sentry::capture_error(&e);
        BadRequest(format!("Failed to parse AniList token response: {e}"))
    })?;

    let token_expires_at = token_response
        .expires_in
        .map(|secs| Utc::now() + Duration::seconds(secs));

    info!("Fetching User data ...");
    let user_id = fetch_viewer_id(&state.client, &token_response.access_token).await?;
    info!("User data fetched successfully");

    upsert_oauth_credentials(
        &state_token.0,
        user_id,
        &token_response.access_token,
        token_response.refresh_token.as_deref(),
        token_expires_at,
        &state.pool,
    )
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        BadRequest(format!("Failed to save OAuth credentials: {e}"))
    })?;

    info!("Saved OAuth credentials for Discord user");
    Ok("Success".to_string())
}
