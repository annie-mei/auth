#[macro_use]
extern crate rocket;

use std::collections::HashMap;

use anyhow::anyhow;
use rocket::{
    response::{status::BadRequest, Redirect},
    State,
};
use serde::Deserialize;
use shuttle_secrets::SecretStore;
use url::Url;

#[get("/login")]
async fn login(state: &State<MyState>) -> Redirect {
    const ANILIST_BASE: &str = "https://anilist.co/api/v2/oauth/authorize";
    let params = [
        ("client_id", state.client_id.as_str()),
        ("redirect_uri", state.redirect_uri.as_str()),
        ("response_type", "code"),
    ];
    let url = Url::parse_with_params(ANILIST_BASE, &params).unwrap();

    Redirect::to(url.to_string())
}

#[get("/authorized?<code>")]
async fn authorized(code: String, state: &State<MyState>) -> Result<String, BadRequest<String>> {
    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct TokenResponse {
        token_type: String,
        expires_in: i32,
        access_token: String,
        refresh_token: String,
    }

    const ANILIST_BASE: &str = "https://anilist.co/api/v2/oauth/token";
    let params = HashMap::from([
        ("grant_type", "authorization_code"),
        ("client_id", state.client_id.as_str()),
        ("client_secret", state.client_secret.as_str()),
        ("redirect_uri", state.redirect_uri.as_str()),
        ("code", code.as_str()),
        ("code", code.as_str()),
    ]);

    let response = state
        .client
        .post(ANILIST_BASE)
        .json(&params)
        .send()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    // If the response fails to parse, return an error.
    // We want the user to try again.
    response
        .json::<TokenResponse>()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    Ok("success".to_string())
}

struct MyState {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    client: reqwest::Client,
}

#[shuttle_runtime::main]
async fn rocket(
    #[shuttle_secrets::Secrets] secret_store: SecretStore,
) -> shuttle_rocket::ShuttleRocket {
    // get secret defined in `Secrets.toml` file.
    let client_id = if let Some(client_id) = secret_store.get("ANILIST_CLIENT_ID") {
        client_id
    } else {
        return Err(anyhow!("Anilist Client ID was not found").into());
    };

    let client_secret = if let Some(client_secret) = secret_store.get("ANILIST_SECRET") {
        client_secret
    } else {
        return Err(anyhow!("Anilist Secret was not found").into());
    };

    let redirect_uri = if let Some(redirect_uri) = secret_store.get("REDIRECT_URL") {
        redirect_uri
    } else {
        return Err(anyhow!("Anilist Redirect URL was not found").into());
    };

    let state = MyState {
        client_id,
        client_secret,
        redirect_uri,
        client: reqwest::Client::new(),
    };
    let rocket = rocket::build()
        .mount("/", routes![login, authorized])
        .manage(state);

    Ok(rocket.into())
}
