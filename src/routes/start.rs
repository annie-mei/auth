use crate::utils::{
    consts::ANILIST_AUTH,
    functions::{get_state_token, insert_oauth_session, verify_oauth_context},
    observability::{configure_oauth_scope, identifier_fingerprint},
    structs::MyState,
};

use rocket::{State, response::Redirect, response::status::BadRequest};
use url::Url;

#[get("/oauth/anilist/start?<ctx>")]
#[tracing::instrument(
    name = "oauth.start",
    skip(state, ctx),
    fields(discord_user_fingerprint = tracing::field::Empty, context_valid = tracing::field::Empty)
)]
pub async fn start(ctx: &str, state: &State<MyState>) -> Result<Redirect, BadRequest<String>> {
    let span = tracing::Span::current();
    let payload = verify_oauth_context(
        ctx,
        &state.context_signing_secret,
        state.context_ttl_seconds,
    )
    .map_err(|_| {
        span.record("context_valid", false);
        info!("OAuth start rejected: invalid or expired context");
        BadRequest("Invalid or expired OAuth context".to_string())
    })?;
    span.record("context_valid", true);

    let discord_user_fingerprint =
        identifier_fingerprint(&payload.discord_user_id, &state.user_id_hash_salt);
    span.record("discord_user_fingerprint", &discord_user_fingerprint);

    let state_token = get_state_token();
    let params = [
        ("client_id", state.client_id.as_str()),
        ("redirect_uri", state.redirect_uri.as_str()),
        ("response_type", "code"),
        ("state", state_token.as_str()),
    ];
    let url = Url::parse_with_params(ANILIST_AUTH, &params)
        .map_err(|e| BadRequest(format!("Failed to build AniList auth URL: {e}")))?;

    insert_oauth_session(
        &state_token,
        &payload.discord_user_id,
        state.state_ttl_seconds,
        state.user_id_hash_salt.as_str(),
        &state.pool,
    )
    .await
    .map_err(|e| {
        sentry::with_scope(
            |scope| {
                configure_oauth_scope(
                    scope,
                    "oauth.start.create_session",
                    Some(discord_user_fingerprint.as_str()),
                )
            },
            || sentry::capture_error(&e),
        );
        error!("Failed to create OAuth session");
        BadRequest("Failed to create OAuth session. Please try again.".to_string())
    })?;

    info!("Created OAuth session");
    Ok(Redirect::to(url.to_string()))
}

#[cfg(test)]
mod tests {
    use super::start;
    use crate::utils::{
        functions::verify_oauth_context,
        structs::{MyState, StateToken},
    };

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Utc;
    use hmac::{Hmac, KeyInit, Mac};
    use rocket::{Config, http::Status, local::asynchronous::Client, routes};
    use serde_json::json;
    use sha2::Sha256;
    use sqlx::{Pool, Postgres};
    use url::Url;

    const TEST_CONTEXT_SECRET: &str = "test-oauth-context-secret-for-unit-tests";

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

    #[get("/consume?<state>")]
    fn consume(state: &str, _state_token: StateToken) -> &'static str {
        let _ = state;
        "ok"
    }

    fn build_test_rocket(pool: Pool<Postgres>) -> rocket::Rocket<rocket::Build> {
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
            token_endpoint: "https://anilist.co/api/v2/oauth/token".to_string(),
            user_endpoint: "https://graphql.anilist.co".to_string(),
            client: reqwest::Client::new(),
            pool,
        };

        rocket::custom(figment)
            .mount("/", routes![start])
            .manage(state)
    }

    fn build_test_rocket_with_consume(pool: Pool<Postgres>) -> rocket::Rocket<rocket::Build> {
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
            token_endpoint: "https://anilist.co/api/v2/oauth/token".to_string(),
            user_endpoint: "https://graphql.anilist.co".to_string(),
            client: reqwest::Client::new(),
            pool,
        };

        rocket::custom(figment)
            .mount("/", routes![start, consume])
            .manage(state)
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn start_redirects_to_anilist(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(pool.clone()))
            .await
            .expect("rocket client should build");
        let response = client.get(signed_start_url("123456789")).dispatch().await;

        assert_eq!(response.status(), Status::SeeOther);
        let location = response
            .headers()
            .get_one("location")
            .expect("start should redirect");
        assert!(location.contains("anilist.co"));

        drop(response);
        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn start_rejects_invalid_context(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(pool.clone()))
            .await
            .expect("rocket client should build");
        let response = client
            .get("/oauth/anilist/start?ctx=not-a-valid-context")
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);

        drop(response);
        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn start_does_not_set_cookies(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(pool.clone()))
            .await
            .expect("rocket client should build");
        let response = client.get(signed_start_url("123456789")).dispatch().await;

        assert!(
            response.headers().get_one("set-cookie").is_none(),
            "start should not set any cookies"
        );

        drop(response);
        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn state_session_is_single_use(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket_with_consume(pool.clone()))
            .await
            .expect("rocket client should build");

        let response = client.get(signed_start_url("987654321")).dispatch().await;
        let redirect_url = response
            .headers()
            .get_one("location")
            .expect("start should redirect");
        let state = Url::parse(redirect_url)
            .expect("redirect URL should parse")
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .expect("redirect URL should include state param");
        drop(response);

        let first = client
            .get(format!("/consume?state={state}"))
            .dispatch()
            .await;
        assert_eq!(first.status(), Status::Ok);

        let replay = client
            .get(format!("/consume?state={state}"))
            .dispatch()
            .await;
        assert_eq!(replay.status(), Status::BadRequest);

        drop(first);
        drop(replay);
        drop(client);
        pool.close().await;
    }

    #[test]
    fn verify_rejects_expired_context() {
        type HmacSha256 = Hmac<Sha256>;

        let now = Utc::now().timestamp();
        let payload = json!({
            "v": 1,
            "discord_user_id": "user1",
            "interaction_id": "456",
            "nonce": "nonce",
            "iat": now - 600,
            "exp": now - 1,
        });
        let payload_segment =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload should serialize"));
        let mut mac = HmacSha256::new_from_slice(TEST_CONTEXT_SECRET.as_bytes()).expect("HMAC key");
        mac.update(payload_segment.as_bytes());
        let signature_segment = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let ctx = format!("{payload_segment}.{signature_segment}");

        assert!(verify_oauth_context(&ctx, TEST_CONTEXT_SECRET, 300).is_err());
    }
}
