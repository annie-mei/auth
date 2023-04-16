use crate::utils::{consts::ANILIST_AUTH, structs::MyState};

use rocket::{response::Redirect, State};
use url::Url;

#[get("/login")]
pub async fn login(state: &State<MyState>) -> Redirect {
    let params = [
        ("client_id", state.client_id.as_str()),
        ("redirect_uri", state.redirect_uri.as_str()),
        ("response_type", "code"),
    ];
    let url = Url::parse_with_params(ANILIST_AUTH, &params).unwrap();

    Redirect::to(url.to_string())
}
