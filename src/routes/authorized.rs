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

#[cfg(test)]
mod tests {
    use super::authorized;
    use crate::{
        routes::login::login,
        utils::{
            functions::fetch_credential_by_discord_user,
            structs::{CallbackResponse, MyState},
        },
    };
    use rocket::{Config, http::Status, local::asynchronous::Client, routes};
    use sqlx::{Pool, Postgres};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn build_test_rocket(
        pool: Pool<Postgres>,
        token_endpoint: String,
        user_endpoint: String,
    ) -> rocket::Rocket<rocket::Build> {
        let figment =
            Config::figment().merge(("secret_key", "0123456789abcdef0123456789abcdef0123456789A="));

        let state = MyState {
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
            redirect_uri: "http://127.0.0.1:8000/authorized".to_string(),
            token_endpoint,
            user_endpoint,
            client: reqwest::Client::new(),
            pool,
        };

        rocket::custom(figment)
            .mount("/", routes![login, authorized])
            .manage(state)
    }

    async fn login_and_extract_state(client: &Client) -> String {
        let response = client
            .get("/login?discord_user_id=555666777888")
            .dispatch()
            .await;
        let location = response
            .headers()
            .get_one("location")
            .expect("login should redirect");
        url::Url::parse(location)
            .expect("redirect URL should parse")
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.to_string())
            .expect("redirect URL should contain state")
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_happy_path_persists_oauth_credentials(pool: Pool<Postgres>) {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access_1",
                "refresh_token": "refresh_1",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "Viewer": { "id": 12345 } }
            })))
            .mount(&mock_server)
            .await;

        let client = Client::tracked(build_test_rocket(
            pool.clone(),
            format!("{}/token", mock_server.uri()),
            format!("{}/graphql", mock_server.uri()),
        ))
        .await
        .expect("rocket client should build");

        let state = login_and_extract_state(&client).await;
        let response = client
            .get(format!("/authorized?state={state}&code=auth_code_1"))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let body = response
            .into_string()
            .await
            .expect("response should contain JSON");
        let callback: CallbackResponse =
            serde_json::from_str(body.as_str()).expect("callback response should deserialize");
        assert_eq!(callback.status, "success");
        assert_eq!(callback.code, "authorized");

        let persisted = fetch_credential_by_discord_user("555666777888", &pool)
            .await
            .expect("fetch should not error")
            .expect("credential should be persisted");

        assert_eq!(persisted.discord_user_id, "555666777888");
        assert_eq!(persisted.anilist_id, 12345);
        assert_eq!(persisted.access_token, "access_1");
        assert_eq!(persisted.refresh_token.as_deref(), Some("refresh_1"));
        assert!(persisted.token_expires_at.is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_invalid_grant_returns_friendly_error(pool: Pool<Postgres>) {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .mount(&mock_server)
            .await;

        let client = Client::tracked(build_test_rocket(
            pool.clone(),
            format!("{}/token", mock_server.uri()),
            format!("{}/graphql", mock_server.uri()),
        ))
        .await
        .expect("rocket client should build");

        let state = login_and_extract_state(&client).await;
        let response = client
            .get(format!("/authorized?state={state}&code=bad_code"))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
        let body = response
            .into_string()
            .await
            .expect("response should contain JSON");
        let callback: CallbackResponse =
            serde_json::from_str(body.as_str()).expect("callback response should deserialize");
        assert_eq!(callback.status, "error");
        assert_eq!(callback.code, "token_exchange_failed");
        assert!(callback.message.contains("invalid or expired"));

        let persisted = fetch_credential_by_discord_user("555666777888", &pool)
            .await
            .expect("fetch should not error");
        assert!(persisted.is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_handles_access_denied_callback(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(
            pool.clone(),
            "https://anilist.co/api/v2/oauth/token".to_string(),
            "https://graphql.anilist.co".to_string(),
        ))
        .await
        .expect("rocket client should build");

        let state = login_and_extract_state(&client).await;
        let response = client
            .get(format!(
                "/authorized?state={state}&error=access_denied&error_description=Denied%20by%20user"
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
        let body = response
            .into_string()
            .await
            .expect("response should contain JSON");
        let callback: CallbackResponse =
            serde_json::from_str(body.as_str()).expect("callback response should deserialize");
        assert_eq!(callback.status, "error");
        assert_eq!(callback.code, "oauth_error");
        assert_eq!(callback.message, "Denied by user");

        let persisted = fetch_credential_by_discord_user("555666777888", &pool)
            .await
            .expect("fetch should not error");
        assert!(persisted.is_none());
    }
}
