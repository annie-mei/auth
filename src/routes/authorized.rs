use crate::utils::{
    consts::ANILIST_TOKEN,
    functions::{fetch_viewer_id, save_access_token},
    structs::{MyState, StateToken, TokenResponse},
};

use rocket::{response::status::BadRequest, State};
use serde_json::json;

#[get("/authorized?<code>")]
pub async fn authorized(
    code: String,
    _state_token: StateToken<'_>,
    state: &State<MyState>,
) -> Result<String, BadRequest<String>> {
    info!("Checking state token ...");

    let token_exchange_error =
        |error| BadRequest(format!("AniList token exchange failed: {error}"));

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
        .map_err(token_exchange_error)?
        .error_for_status()
        .map_err(token_exchange_error)?;

    let access_token = response
        .json::<TokenResponse>()
        .await
        .map_err(|e| BadRequest(format!("Failed to parse AniList token response: {e}")))?
        .access_token;

    info!("Fetching User data ...");
    let user_id = fetch_viewer_id(&state.client, &access_token).await?;
    info!("User data fetched successfully");

    save_access_token(&access_token, user_id, &state.pool)
        .await
        .map_err(|e| BadRequest(format!("Failed to save access token: {e}")))?;

    info!("Saved access token");
    Ok("Success".to_string())
}
