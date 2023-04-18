use crate::utils::{
    consts::ANILIST_TOKEN,
    functions::{fetch_viewer_id, save_access_token},
    structs::{MyState, StateToken, TokenResponse},
};
use std::collections::HashMap;

use rocket::{log::private::info, response::status::BadRequest, State};

#[get("/authorized?<code>")]
pub async fn authorized(
    code: String,
    _state_token: StateToken<'_>,
    state: &State<MyState>,
) -> Result<String, BadRequest<String>> {
    info!("Checking state token ...");

    let params = HashMap::from([
        ("grant_type", "authorization_code"),
        ("client_id", state.client_id.as_str()),
        ("client_secret", state.client_secret.as_str()),
        ("redirect_uri", state.redirect_uri.as_str()),
        ("code", code.as_str()),
    ]);

    let response = state
        .client
        .post(ANILIST_TOKEN)
        .json(&params)
        .send()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    // If the response fails to parse, return an error.
    // We want the user to try again.
    let access_token = response
        .json::<TokenResponse>()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?
        .access_token;

    info!("Fetching User data ...");

    info!("User data fetched successfully! ...");

    match fetch_viewer_id(state.client.clone(), access_token.clone()).await {
        Ok(id) => {
            info!("User ID: {:#?}", id);
            let response = save_access_token(access_token, id, &state.pool).await;
            match response {
                Ok(_) => info!("Saved access token"),
                Err(e) => {
                    let message = format!("Failed to save access token: {:#?}", e);
                    info!("Error: {:#?}", message);
                    return Err(BadRequest(Some(message)));
                }
            }
            Ok("Success".to_string())
        }
        Err(e) => {
            let message = format!("Failed to fetch viewer ID: {:#?}", e);
            info!("Error: {:#?}", message);
            Err(BadRequest(Some(message)))
        }
    }
}
