use crate::utils::{
    consts::ANILIST_AUTH,
    functions::{get_state_token, insert_oauth_session, verify_bot_signature},
    structs::MyState,
};

use rocket::{State, response::Redirect, response::status::BadRequest};
use url::Url;

#[get("/login?<discord_user_id>&<ts>&<sig>")]
#[tracing::instrument(name = "login", skip(state, sig))]
pub async fn login(
    discord_user_id: &str,
    ts: &str,
    sig: &str,
    state: &State<MyState>,
) -> Result<Redirect, BadRequest<String>> {
    if !verify_bot_signature(discord_user_id, ts, sig, &state.bot_auth_secret) {
        info!("Login rejected: invalid or expired bot signature");
        return Err(BadRequest("Invalid or expired login signature".to_string()));
    }

    let state_token = get_state_token();
    let params = [
        ("client_id", state.client_id.as_str()),
        ("redirect_uri", state.redirect_uri.as_str()),
        ("response_type", "code"),
        ("state", state_token.as_str()),
    ];
    let url = Url::parse_with_params(ANILIST_AUTH, &params)
        .map_err(|e| BadRequest(format!("Failed to build AniList auth URL: {e}")))?;

    insert_oauth_session(&state_token, discord_user_id, &state.pool)
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            BadRequest(format!("Failed to create OAuth session: {e}"))
        })?;

    info!("Created OAuth session for Discord user");
    Ok(Redirect::to(url.to_string()))
}

#[cfg(test)]
mod tests {
    use super::login;
    use crate::utils::{
        functions::verify_bot_signature,
        structs::{MyState, StateToken},
    };

    use chrono::Utc;
    use hmac::{Hmac, Mac};
    use rocket::{Config, http::Status, local::asynchronous::Client, routes};
    use sha2::Sha256;
    use sqlx::{Pool, Postgres};
    use url::Url;

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

    /// Helper route that exercises the StateToken guard for integration testing.
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
            redirect_uri: "http://127.0.0.1:8000/authorized".to_string(),
            bot_auth_secret: TEST_BOT_SECRET.to_string(),
            token_endpoint: "https://anilist.co/api/v2/oauth/token".to_string(),
            user_endpoint: "https://graphql.anilist.co".to_string(),
            client: reqwest::Client::new(),
            pool,
        };

        rocket::custom(figment)
            .mount("/", routes![login])
            .manage(state)
    }

    fn build_test_rocket_with_consume(pool: Pool<Postgres>) -> rocket::Rocket<rocket::Build> {
        let figment =
            Config::figment().merge(("secret_key", "0123456789abcdef0123456789abcdef0123456789A="));

        let state = MyState {
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
            redirect_uri: "http://127.0.0.1:8000/authorized".to_string(),
            bot_auth_secret: TEST_BOT_SECRET.to_string(),
            token_endpoint: "https://anilist.co/api/v2/oauth/token".to_string(),
            user_endpoint: "https://graphql.anilist.co".to_string(),
            client: reqwest::Client::new(),
            pool,
        };

        rocket::custom(figment)
            .mount("/", routes![login, consume])
            .manage(state)
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn login_redirects_to_anilist(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(pool))
            .await
            .expect("rocket client should build");
        let response = client.get(signed_login_url("123456789")).dispatch().await;

        assert_eq!(response.status(), Status::SeeOther);
        let location = response
            .headers()
            .get_one("location")
            .expect("login should redirect");
        assert!(location.contains("anilist.co"));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn login_rejects_invalid_signature(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(pool))
            .await
            .expect("rocket client should build");
        let ts = Utc::now().timestamp();
        let response = client
            .get(format!(
                "/login?discord_user_id=123&ts={ts}&sig=0000000000000000"
            ))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn login_does_not_set_cookies(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(pool))
            .await
            .expect("rocket client should build");
        let response = client.get(signed_login_url("123456789")).dispatch().await;

        assert!(
            response.headers().get_one("set-cookie").is_none(),
            "login should not set any cookies"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn state_session_is_single_use(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket_with_consume(pool))
            .await
            .expect("rocket client should build");

        let response = client.get(signed_login_url("987654321")).dispatch().await;
        let redirect_url = response
            .headers()
            .get_one("location")
            .expect("login should redirect");
        let state = Url::parse(redirect_url)
            .expect("redirect URL should parse")
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .expect("redirect URL should include state param");

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
    }

    #[test]
    fn verify_rejects_expired_timestamp() {
        let old_ts = (Utc::now().timestamp() - 400).to_string();
        let sig = sign_login("user1", old_ts.parse().unwrap());
        assert!(!verify_bot_signature(
            "user1",
            &old_ts,
            &sig,
            TEST_BOT_SECRET
        ));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let ts = Utc::now().timestamp();
        let sig = sign_login("user1", ts);
        assert!(!verify_bot_signature(
            "user1",
            &ts.to_string(),
            &sig,
            "wrong-secret"
        ));
    }
}
