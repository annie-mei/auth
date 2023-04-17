use crate::utils::{consts::ANILIST_AUTH, functions::get_state_token, structs::MyState};

use rocket::{
    http::{Cookie, CookieJar},
    response::Redirect,
    time::{Duration, OffsetDateTime},
    State,
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
    let cookie = Cookie::build("state", state_token)
        .expires(OffsetDateTime::now_utc() + Duration::minutes(5))
        .finish();

    jar.add_private(cookie);

    Redirect::to(url.to_string())
}
