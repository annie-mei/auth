use crate::utils::{
    functions::{
        UpsertOAuthCredentialsError, exchange_code_for_token, fetch_viewer_id, token_expires_at,
        upsert_oauth_credentials,
    },
    observability::{configure_oauth_scope, identifier_fingerprint, record_identifier_fingerprint},
    structs::{MyState, StateToken, StateTokenError},
};

use rocket::{
    State,
    http::Status,
    response::{content::RawHtml, status::Custom},
};

#[get("/oauth/anilist/callback?<code>&<error>&<error_description>")]
#[tracing::instrument(
    name = "oauth.callback",
    skip_all,
    fields(
        discord_user_fingerprint = tracing::field::Empty,
        anilist_fingerprint = tracing::field::Empty,
        oauth_error_code = tracing::field::Empty
    )
)]
pub async fn authorized(
    code: Option<&str>,
    error: Option<&str>,
    error_description: Option<&str>,
    state_token: Result<StateToken, StateTokenError>,
    state: &State<MyState>,
) -> Custom<RawHtml<String>> {
    let span = tracing::Span::current();
    let state_token = match state_token {
        Ok(state_token) => state_token,
        Err(error) => return callback_error_for_state_token(error),
    };

    let discord_user_fingerprint = identifier_fingerprint(&state_token.0, &state.user_id_hash_salt);
    span.record("discord_user_fingerprint", &discord_user_fingerprint);
    info!("State token validated; beginning AniList token exchange");

    if let Some(error_code) = error {
        span.record("oauth_error_code", error_code);
        let has_error_description = error_description.is_some();
        info!(
            "AniList callback returned an OAuth error (code: {error_code}, has_description: {has_error_description})"
        );
        let message = match error_code {
            "access_denied" => "Authorization was denied on AniList. Please try again.",
            _ => "AniList authorization failed. Please try again.",
        };

        return callback_error(message, Status::BadRequest);
    }

    let Some(code) = code else {
        return callback_error(
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
        Some(discord_user_fingerprint.as_str()),
    )
    .await
    {
        Ok(response) => response,
        Err(error) => return callback_error(error.message(), error.status()),
    };

    let token_expires_at = token_expires_at(token_response.expires_in);

    info!("Fetching User data ...");
    let anilist_id = match fetch_viewer_id(
        &state.client,
        state.user_endpoint.as_str(),
        &token_response.access_token,
        Some(discord_user_fingerprint.as_str()),
    )
    .await
    {
        Ok(user_id) => {
            record_identifier_fingerprint(
                &span,
                "anilist_fingerprint",
                &user_id.to_string(),
                &state.user_id_hash_salt,
            );
            user_id
        }
        Err(error) => return callback_error(error.message(), error.status()),
    };
    info!("User data fetched successfully");

    if let Err(error) = upsert_oauth_credentials(
        &state_token.0,
        anilist_id,
        &token_response.access_token,
        token_response.refresh_token.as_deref(),
        token_expires_at,
        state.user_id_hash_salt.as_str(),
        &state.pool,
    )
    .await
    {
        return match error {
            UpsertOAuthCredentialsError::AlreadyLinked => callback_error(
                "This AniList account is already linked to another Discord user.",
                Status::BadRequest,
            ),
            UpsertOAuthCredentialsError::Db(error) => {
                sentry::with_scope(
                    |scope| {
                        configure_oauth_scope(
                            scope,
                            "oauth.callback.upsert_oauth_credentials",
                            Some(discord_user_fingerprint.as_str()),
                        )
                    },
                    || sentry::capture_error(&error),
                );
                error!("Failed to persist AniList credentials");
                callback_error(
                    "Failed to save AniList credentials. Please retry.",
                    Status::InternalServerError,
                )
            }
        };
    }

    info!("Saved OAuth credentials for Discord user");
    callback_success("AniList account connected successfully.")
}

fn callback_success(message: &str) -> Custom<RawHtml<String>> {
    Custom(Status::Ok, RawHtml(render_page(true, message)))
}

fn callback_error(message: &str, status: Status) -> Custom<RawHtml<String>> {
    Custom(status, RawHtml(render_page(false, message)))
}

fn callback_error_for_state_token(error: StateTokenError) -> Custom<RawHtml<String>> {
    match error {
        StateTokenError::Missing => callback_error(
            "State parameter is missing from the callback.",
            Status::BadRequest,
        ),
        StateTokenError::Invalid => callback_error(
            "State parameter is invalid. Please restart the AniList login flow.",
            Status::BadRequest,
        ),
        StateTokenError::Expired => callback_error(
            "State parameter has expired. Please restart the AniList login flow.",
            Status::BadRequest,
        ),
        StateTokenError::Replayed => callback_error(
            "This login link has already been used. Please restart the AniList login flow.",
            Status::BadRequest,
        ),
        StateTokenError::Internal => callback_error(
            "Failed to validate the AniList login state. Please retry.",
            Status::InternalServerError,
        ),
    }
}

fn render_page(success: bool, message: &str) -> String {
    let (title, heading, hint, accent, icon_bg, icon_svg) = if success {
        (
            "Connected - Annie Mei",
            "Account Connected",
            "You can close this tab now.",
            "#22c55e",
            "rgba(34, 197, 94, 0.12)",
            r##"<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 12l3 3 5-6"/></svg>"##,
        )
    } else {
        (
            "Error - Annie Mei",
            "Something Went Wrong",
            "Please try again from Discord.",
            "#ef4444",
            "rgba(239, 68, 68, 0.12)",
            r##"<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6"/><path d="M9 9l6 6"/></svg>"##,
        )
    };

    let escaped_message = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="icon" type="image/png" href="/static/favicon.png">
<style>
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{
    min-height:100vh;
    display:flex;align-items:center;justify-content:center;
    background:linear-gradient(145deg,#0f0f13 0%,#1a1a2e 100%);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;
    color:#e4e4e7;
    padding:1rem;
  }}
  .card{{
    width:100%;max-width:420px;
    background:rgba(255,255,255,0.04);
    border:1px solid rgba(255,255,255,0.08);
    border-radius:16px;
    backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
    box-shadow:0 8px 32px rgba(0,0,0,0.3);
    padding:2.5rem 2rem;
    text-align:center;
    animation:fadeSlideIn .5s ease-out;
  }}
  .icon{{
    width:72px;height:72px;
    border-radius:50%;
    background:{icon_bg};
    display:flex;align-items:center;justify-content:center;
    margin:0 auto 1.5rem;
    animation:scaleIn .4s ease-out .15s both;
  }}
  h1{{
    font-size:1.375rem;font-weight:600;
    color:{accent};
    margin-bottom:.75rem;
  }}
  .message{{
    font-size:.9375rem;line-height:1.6;
    color:#a1a1aa;
    margin-bottom:1.5rem;
  }}
  .hint{{
    font-size:.8125rem;
    color:#52525b;
  }}
  .brand{{
    margin-top:2rem;
    font-size:.75rem;
    color:#3f3f46;
    letter-spacing:.04em;
  }}
  @keyframes fadeSlideIn{{
    from{{opacity:0;transform:translateY(12px)}}
    to{{opacity:1;transform:translateY(0)}}
  }}
  @keyframes scaleIn{{
    from{{opacity:0;transform:scale(.6)}}
    to{{opacity:1;transform:scale(1)}}
  }}
</style>
</head>
<body>
  <div class="card">
    <div class="icon">{icon_svg}</div>
    <h1>{heading}</h1>
    <p class="message">{escaped_message}</p>
    <p class="hint">{hint}</p>
    <p class="brand">Annie Mei</p>
  </div>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::authorized;
    use crate::{
        routes::start::start,
        utils::{
            functions::{fetch_credential_by_discord_user, upsert_oauth_credentials},
            structs::MyState,
        },
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Utc;
    use hmac::{Hmac, KeyInit, Mac};
    use rocket::{Config, http::Status, local::asynchronous::Client, routes};
    use serde_json::json;
    use sha2::Sha256;
    use sqlx::{Pool, Postgres};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    const TEST_CONTEXT_SECRET: &str = "test-oauth-context-secret-for-unit-tests";
    const TEST_USERID_HASH_SALT: &str = "test-userid-hash-salt";

    fn signed_start_url(discord_user_id: &str) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let now = Utc::now().timestamp();
        let payload = json!({
            "v": 1,
            "discord_user_id": discord_user_id,
            "guild_id": "987654321098765432",
            "interaction_id": "12222333344445555",
            "nonce": "bM0XvTa5yT4K0z2yPxtA3A",
            "iat": now,
            "exp": now + 300,
        });
        let payload_segment =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload should serialize"));
        let mut mac = HmacSha256::new_from_slice(TEST_CONTEXT_SECRET.as_bytes()).expect("HMAC key");
        mac.update(payload_segment.as_bytes());
        let signature_segment = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        format!("/oauth/anilist/start?ctx={payload_segment}.{signature_segment}")
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
            redirect_uri: "http://127.0.0.1:8000/oauth/anilist/callback".to_string(),
            context_signing_secret: TEST_CONTEXT_SECRET.to_string(),
            user_id_hash_salt: "test-userid-hash-salt".to_string(),
            context_ttl_seconds: 300,
            state_ttl_seconds: 600,
            token_endpoint,
            user_endpoint,
            client: reqwest::Client::new(),
            pool,
        };

        rocket::custom(figment)
            .mount("/", routes![start, authorized])
            .manage(state)
    }

    async fn start_and_extract_state(client: &Client) -> String {
        let response = client
            .get(signed_start_url("555666777888"))
            .dispatch()
            .await;
        let location = response
            .headers()
            .get_one("location")
            .expect("start should redirect");
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

        let state = start_and_extract_state(&client).await;
        let response = client
            .get(format!(
                "/oauth/anilist/callback?state={state}&code=auth_code_1"
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let body = response
            .into_string()
            .await
            .expect("response should contain HTML");
        assert!(body.contains("Account Connected"));
        assert!(body.contains("AniList account connected successfully."));

        let persisted =
            fetch_credential_by_discord_user("555666777888", TEST_USERID_HASH_SALT, &pool)
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

        let state = start_and_extract_state(&client).await;
        let response = client
            .get(format!(
                "/oauth/anilist/callback?state={state}&code=bad_code"
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
        let body = response
            .into_string()
            .await
            .expect("response should contain HTML");
        assert!(body.contains("Something Went Wrong"));
        assert!(body.contains("invalid or expired"));

        let persisted =
            fetch_credential_by_discord_user("555666777888", TEST_USERID_HASH_SALT, &pool)
                .await
                .expect("fetch should not error");
        assert!(persisted.is_none());

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_invalid_client_returns_bad_gateway(pool: Pool<Postgres>) {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client"
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

        let state = start_and_extract_state(&client).await;
        let response = client
            .get(format!(
                "/oauth/anilist/callback?state={state}&code=bad_client"
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadGateway);
        let body = response
            .into_string()
            .await
            .expect("response should contain HTML");
        assert!(body.contains("Something Went Wrong"));
        assert!(body.contains("AniList OAuth client configuration is invalid"));

        let persisted =
            fetch_credential_by_discord_user("555666777888", TEST_USERID_HASH_SALT, &pool)
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

        let state = start_and_extract_state(&client).await;
        let response = client
            .get(format!(
                "/oauth/anilist/callback?state={state}&code=server_error_code"
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadGateway);
        let body = response
            .into_string()
            .await
            .expect("response should contain HTML");
        assert!(body.contains("Something Went Wrong"));
        assert!(body.contains("AniList is temporarily unavailable. Please try again."));

        let persisted =
            fetch_credential_by_discord_user("555666777888", TEST_USERID_HASH_SALT, &pool)
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

        let state = start_and_extract_state(&client).await;
        let response = client
            .get(format!(
                "/oauth/anilist/callback?state={state}&code=bad_payload"
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadGateway);
        let body = response
            .into_string()
            .await
            .expect("response should contain HTML");
        assert!(body.contains("Something Went Wrong"));
        assert!(body.contains("Failed to parse AniList token response. Please try again."));

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

        let state = start_and_extract_state(&client).await;
        let response = client
            .get(format!(
                "/oauth/anilist/callback?state={state}&error=access_denied&error_description=Denied%20by%20user"
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
        let body = response
            .into_string()
            .await
            .expect("response should contain HTML");
        assert!(body.contains("Something Went Wrong"));
        assert!(body.contains("Authorization was denied on AniList. Please try again."));

        let persisted =
            fetch_credential_by_discord_user("555666777888", TEST_USERID_HASH_SALT, &pool)
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

        let state = start_and_extract_state(&client).await;
        let response = client
            .get(format!(
                "/oauth/anilist/callback?state={state}&code=auth_code_1"
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadGateway);
        let body = response
            .into_string()
            .await
            .expect("response should contain HTML");
        assert!(body.contains("Something Went Wrong"));
        assert!(body.contains("Failed to parse AniList viewer response. Please try again."));

        let persisted =
            fetch_credential_by_discord_user("555666777888", TEST_USERID_HASH_SALT, &pool)
                .await
                .expect("fetch should not error");
        assert!(persisted.is_none());

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_invalid_state_returns_error_page(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(
            pool.clone(),
            "https://anilist.co/api/v2/oauth/token".to_string(),
            "https://graphql.anilist.co".to_string(),
        ))
        .await
        .expect("rocket client should build");

        let response = client
            .get("/oauth/anilist/callback?state=invalid_state&code=auth_code_1")
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
        let body = response
            .into_string()
            .await
            .expect("response should contain HTML");
        assert!(body.contains("Something Went Wrong"));
        assert!(body.contains("Please restart"));

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_replayed_state_returns_error_page(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(
            pool.clone(),
            "https://anilist.co/api/v2/oauth/token".to_string(),
            "https://graphql.anilist.co".to_string(),
        ))
        .await
        .expect("rocket client should build");

        let state = start_and_extract_state(&client).await;
        let first_response = client
            .get(format!(
                "/oauth/anilist/callback?state={state}&error=access_denied&error_description=Denied%20by%20user"
            ))
            .dispatch()
            .await;
        assert_eq!(first_response.status(), Status::BadRequest);
        drop(first_response);

        let replay_response = client
            .get(format!(
                "/oauth/anilist/callback?state={state}&code=auth_code_1"
            ))
            .dispatch()
            .await;

        assert_eq!(replay_response.status(), Status::BadRequest);
        let body = replay_response
            .into_string()
            .await
            .expect("response should contain HTML");
        assert!(body.contains("Something Went Wrong"));
        assert!(body.contains("already been used"));

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn authorized_rejects_anilist_account_linked_to_another_discord_user(
        pool: Pool<Postgres>,
    ) {
        upsert_oauth_credentials(
            "existing_user",
            12345,
            "existing_access",
            None,
            None,
            TEST_USERID_HASH_SALT,
            &pool,
        )
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

        let state = start_and_extract_state(&client).await;
        let response = client
            .get(format!(
                "/oauth/anilist/callback?state={state}&code=auth_code_1"
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
        let body = response
            .into_string()
            .await
            .expect("response should contain HTML");
        assert!(body.contains("Something Went Wrong"));
        assert!(body.contains("already linked to another Discord user"));

        let existing =
            fetch_credential_by_discord_user("existing_user", TEST_USERID_HASH_SALT, &pool)
                .await
                .expect("fetch should not error")
                .expect("existing credential should remain");
        assert_eq!(existing.access_token, "existing_access");

        let conflicting =
            fetch_credential_by_discord_user("555666777888", TEST_USERID_HASH_SALT, &pool)
                .await
                .expect("fetch should not error");
        assert!(conflicting.is_none());

        drop(client);
        pool.close().await;
    }
}
