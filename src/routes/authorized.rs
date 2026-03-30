use crate::utils::{
    functions::{
        UpsertOAuthCredentialsError, exchange_code_for_token, fetch_viewer_id, token_expires_at,
        upsert_oauth_credentials,
    },
    structs::{CallbackResponse, MyState, StateToken, StateTokenError},
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
    state_token: Result<StateToken, StateTokenError>,
    state: &State<MyState>,
) -> Custom<Json<CallbackResponse>> {
    let state_token = match state_token {
        Ok(state_token) => state_token,
        Err(error) => return callback_error_for_state_token(error),
    };

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
        state.token_endpoint.as_str(),
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
    let anilist_id = match fetch_viewer_id(
        &state.client,
        state.user_endpoint.as_str(),
        &token_response.access_token,
    )
    .await
    {
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
        return match error {
            UpsertOAuthCredentialsError::AlreadyLinked => callback_error(
                "already_linked",
                "This AniList account is already linked to another Discord user.",
                Status::BadRequest,
            ),
            UpsertOAuthCredentialsError::Db(error) => {
                sentry::capture_error(&error);
                error!("Failed to persist AniList credentials: {error}");
                callback_error(
                    "persistence_failed",
                    "Failed to save AniList credentials. Please retry.",
                    Status::InternalServerError,
                )
            }
        };
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

fn callback_error_for_state_token(error: StateTokenError) -> Custom<Json<CallbackResponse>> {
    match error {
        StateTokenError::Missing => callback_error(
            "missing_state",
            "State parameter is missing from the callback.",
            Status::BadRequest,
        ),
        StateTokenError::Invalid => callback_error(
            "invalid_state",
            "State parameter is invalid. Please restart the AniList login flow.",
            Status::BadRequest,
        ),
        StateTokenError::Expired => callback_error(
            "expired_state",
            "State parameter has expired. Please restart the AniList login flow.",
            Status::BadRequest,
        ),
        StateTokenError::Replayed => callback_error(
            "replayed_state",
            "This login link has already been used. Please restart the AniList login flow.",
            Status::BadRequest,
        ),
        StateTokenError::Internal => callback_error(
            "state_validation_failed",
            "Failed to validate the AniList login state. Please retry.",
            Status::InternalServerError,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::authorized;
    use crate::{
        routes::login::login,
        utils::{
            functions::{fetch_credential_by_discord_user, upsert_oauth_credentials},
            structs::{CallbackResponse, MyState},
        },
    };
    use chrono::Utc;
    use hmac::{Hmac, Mac};
    use rocket::{Config, http::Status, local::asynchronous::Client, routes};
    use sha2::Sha256;
    use sqlx::{Pool, Postgres};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const TEST_BOT_SECRET: &str = "test-bot-auth-secret-for-unit-tests";

    fn sign_login(discord_user_id: &str, ts: i64) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let message = format!("{discord_user_id}:{ts}");
        let mut mac = HmacSha256::new_from_slice(TEST_BOT_SECRET.as_bytes()).expect("HMAC key");
        mac.update(message.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn signed_login_url(discord_user_id: &str) -> String {
        let ts = Utc::now().timestamp();
        let sig = sign_login(discord_user_id, ts);
        format!("/login?discord_user_id={discord_user_id}&ts={ts}&sig={sig}")
    }

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
            bot_auth_secret: TEST_BOT_SECRET.to_string(),
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
            .get(signed_login_url("555666777888"))
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

        drop(client);
        pool.close().await;
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

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_upstream_server_error_returns_user_safe_message(pool: Pool<Postgres>) {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "error": "server_error"
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
            .get(format!("/authorized?state={state}&code=server_error_code"))
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
        assert_eq!(
            callback.message,
            "AniList is temporarily unavailable. Please try again."
        );

        let persisted = fetch_credential_by_discord_user("555666777888", &pool)
            .await
            .expect("fetch should not error");
        assert!(persisted.is_none());

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_token_parse_failure_returns_user_safe_message(pool: Pool<Postgres>) {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token_type": "Bearer"
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
            .get(format!("/authorized?state={state}&code=bad_payload"))
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
        assert_eq!(
            callback.message,
            "Failed to parse AniList token response. Please try again."
        );

        drop(client);
        pool.close().await;
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

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_viewer_parse_failure_returns_user_safe_message(pool: Pool<Postgres>) {
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
                "data": {}
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

        assert_eq!(response.status(), Status::BadGateway);
        let body = response
            .into_string()
            .await
            .expect("response should contain JSON");
        let callback: CallbackResponse =
            serde_json::from_str(body.as_str()).expect("callback response should deserialize");
        assert_eq!(callback.status, "error");
        assert_eq!(callback.code, "viewer_fetch_failed");
        assert_eq!(
            callback.message,
            "Failed to parse AniList viewer response. Please try again."
        );

        let persisted = fetch_credential_by_discord_user("555666777888", &pool)
            .await
            .expect("fetch should not error");
        assert!(persisted.is_none());

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_invalid_state_returns_structured_json(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(
            pool.clone(),
            "https://anilist.co/api/v2/oauth/token".to_string(),
            "https://graphql.anilist.co".to_string(),
        ))
        .await
        .expect("rocket client should build");

        let response = client
            .get("/authorized?state=invalid_state&code=auth_code_1")
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
        assert_eq!(callback.code, "invalid_state");
        assert!(callback.message.contains("Please restart"));

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_replayed_state_returns_structured_json(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(
            pool.clone(),
            "https://anilist.co/api/v2/oauth/token".to_string(),
            "https://graphql.anilist.co".to_string(),
        ))
        .await
        .expect("rocket client should build");

        let state = login_and_extract_state(&client).await;
        let first_response = client
            .get(format!(
                "/authorized?state={state}&error=access_denied&error_description=Denied%20by%20user"
            ))
            .dispatch()
            .await;
        assert_eq!(first_response.status(), Status::BadRequest);
        drop(first_response);

        let replay_response = client
            .get(format!("/authorized?state={state}&code=auth_code_1"))
            .dispatch()
            .await;

        assert_eq!(replay_response.status(), Status::BadRequest);
        let body = replay_response
            .into_string()
            .await
            .expect("response should contain JSON");
        let callback: CallbackResponse =
            serde_json::from_str(body.as_str()).expect("callback response should deserialize");
        assert_eq!(callback.status, "error");
        assert_eq!(callback.code, "replayed_state");

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_rejects_anilist_account_linked_to_another_discord_user(
        pool: Pool<Postgres>,
    ) {
        upsert_oauth_credentials("existing_user", 12345, "existing_access", None, None, &pool)
            .await
            .expect("seed upsert should succeed");

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

        assert_eq!(response.status(), Status::BadRequest);
        let body = response
            .into_string()
            .await
            .expect("response should contain JSON");
        let callback: CallbackResponse =
            serde_json::from_str(body.as_str()).expect("callback response should deserialize");
        assert_eq!(callback.status, "error");
        assert_eq!(callback.code, "already_linked");

        let existing = fetch_credential_by_discord_user("existing_user", &pool)
            .await
            .expect("fetch should not error")
            .expect("existing credential should remain");
        assert_eq!(existing.access_token, "existing_access");

        let conflicting = fetch_credential_by_discord_user("555666777888", &pool)
            .await
            .expect("fetch should not error");
        assert!(conflicting.is_none());

        drop(client);
        pool.close().await;
    }
}
