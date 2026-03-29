use crate::utils::{
    functions::{
        exchange_code_for_token, fetch_viewer_id, token_expires_at, upsert_oauth_credentials,
    },
    structs::{CallbackResponse, MyState, StateToken},
};

use rocket::{
    State,
    http::Status,
    response::{status, status::Custom},
    serde::json::Json,
};

#[get("/authorized?<code>&<error>&<error_description>")]
#[tracing::instrument(name = "authorized", skip_all, fields(discord_user_id))]
pub async fn authorized(
    code: Option<&str>,
    error: Option<&str>,
    error_description: Option<&str>,
    state_token: StateToken,
    state: &State<MyState>,
) -> Custom<Json<CallbackResponse>> {
    tracing::Span::current().record("discord_user_id", state_token.0.as_str());
    info!("State token validated; beginning token exchange");

    sentry::configure_scope(|scope| {
        scope.set_user(Some(sentry::User {
            id: Some(state_token.0.clone()),
            ..Default::default()
        }));
    });

    if let Some(error_code) = error {
        let message = match error_code {
            "access_denied" => "Authorization was denied on AniList. Please try again.",
            _ => "AniList authorization failed. Please try again.",
        };

        return callback_error(
            "oauth_error",
            error_description.unwrap_or(message),
            Status::BadRequest,
        );
    }

    let Some(code) = code else {
        return callback_error(
            "missing_code",
            "Authorization code is missing from the callback.",
            Status::BadRequest,
        );
    };

    let token_response = match exchange_code_for_token(
        &state.client,
        state.client_id.as_str(),
        state.client_secret.as_str(),
        state.redirect_uri.as_str(),
        code,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            return callback_error(
                "token_exchange_failed",
                error.0.as_str(),
                Status::BadRequest,
            );
        }
    };

    let token_expires_at = token_expires_at(token_response.expires_in);

    info!("Fetching User data ...");
    let anilist_id = match fetch_viewer_id(&state.client, &token_response.access_token).await {
        Ok(user_id) => user_id,
        Err(error) => {
            return callback_error("viewer_fetch_failed", error.0.as_str(), Status::BadGateway);
        }
    };
    info!("User data fetched successfully");

    if let Err(error) = upsert_oauth_credentials(
        &state_token.0,
        anilist_id,
        &token_response.access_token,
        token_response.refresh_token.as_deref(),
        token_expires_at,
        &state.pool,
    )
    .await
    {
        sentry::capture_error(&error);
        error!("Failed to persist AniList credentials: {error}");
        return callback_error(
            "persistence_failed",
            "Failed to save AniList credentials. Please retry.",
            Status::InternalServerError,
        );
    }

    info!("Saved OAuth credentials for Discord user");
    callback_success("authorized", "AniList account connected successfully.")
}

fn callback_success(code: &str, message: &str) -> Custom<Json<CallbackResponse>> {
    status::Custom(
        Status::Ok,
        Json(CallbackResponse {
            status: "success".to_string(),
            code: code.to_string(),
            message: message.to_string(),
        }),
    )
}

fn callback_error(code: &str, message: &str, status: Status) -> Custom<Json<CallbackResponse>> {
    status::Custom(
        status,
        Json(CallbackResponse {
            status: "error".to_string(),
            code: code.to_string(),
            message: message.to_string(),
        }),
    )
}
