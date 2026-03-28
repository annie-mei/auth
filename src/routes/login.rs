use crate::utils::{consts::ANILIST_AUTH, functions::get_state_token, structs::MyState};

use rocket::{
    State,
    http::{Cookie, CookieJar, SameSite},
    response::Redirect,
    time::{Duration, OffsetDateTime},
};
use url::Url;

#[get("/login")]
pub async fn login(state: &State<MyState>, jar: &CookieJar<'_>) -> Redirect {
    let state_token = get_state_token();
    let params = [
        ("client_id", state.client_id.as_str()),
        ("redirect_uri", state.redirect_uri.as_str()),
        ("response_type", "code"),
        ("state", state_token.as_str()),
    ];
    let url = Url::parse_with_params(ANILIST_AUTH, &params).unwrap();
    let cookie = Cookie::build(("state", state_token))
        // OAuth returns from AniList as a top-level cross-site navigation, so
        // the state cookie must be sent on the callback request.
        .same_site(SameSite::Lax)
        .expires(OffsetDateTime::now_utc() + Duration::minutes(5))
        .build();

    jar.add_private(cookie);

    Redirect::to(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::login;
    use crate::utils::structs::{MyState, StateToken};

    use rocket::{Config, http::Status, local::asynchronous::Client, routes};
    use sqlx::postgres::PgPoolOptions;
    use url::Url;

    #[get("/consume?<state>")]
    fn consume(state: &str, _state_token: StateToken<'_>) -> &'static str {
        let _ = state;
        "ok"
    }

    fn build_test_rocket() -> rocket::Rocket<rocket::Build> {
        let figment =
            Config::figment().merge(("secret_key", "0123456789abcdef0123456789abcdef0123456789A="));

        let state = MyState {
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
            redirect_uri: "http://127.0.0.1:8000/authorized".to_string(),
            client: reqwest::Client::new(),
            pool: PgPoolOptions::new()
                .connect_lazy("postgres://postgres:postgres@127.0.0.1:5432/annie_mei")
                .expect("lazy pool should build"),
        };

        rocket::custom(figment)
            .mount("/", routes![login, consume])
            .manage(state)
    }

    #[rocket::async_test]
    async fn login_sets_lax_state_cookie() {
        let client = Client::tracked(build_test_rocket())
            .await
            .expect("rocket client should build");
        let response = client.get("/login").dispatch().await;
        let set_cookie = response
            .headers()
            .get_one("set-cookie")
            .expect("login should set a cookie");

        assert!(set_cookie.contains("SameSite=Lax"));
    }

    #[rocket::async_test]
    async fn state_cookie_is_single_use_after_validation() {
        let client = Client::tracked(build_test_rocket())
            .await
            .expect("rocket client should build");
        let response = client.get("/login").dispatch().await;
        let redirect_url = response
            .headers()
            .get_one("location")
            .expect("login should redirect");
        let state = Url::parse(redirect_url)
            .expect("redirect URL should parse")
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .expect("redirect URL should include state");

        let first_response = client
            .get(format!("/consume?state={state}"))
            .dispatch()
            .await;
        assert_eq!(first_response.status(), Status::Ok);

        let replay_response = client
            .get(format!("/consume?state={state}"))
            .dispatch()
            .await;
        assert_eq!(replay_response.status(), Status::BadRequest);
    }
}
