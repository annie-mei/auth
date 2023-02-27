#[macro_use]
extern crate rocket;

use std::collections::HashMap;

use anyhow::anyhow;
use rocket::{
    response::{status::BadRequest, Redirect},
    serde::Deserialize,
    State,
};
use shuttle_secrets::SecretStore;
use url::Url;

#[get("/secret")]
async fn secret(state: &State<MyState>) -> Result<String, BadRequest<String>> {
    Ok(state.client_id.clone())
}

#[get("/login")]
async fn login(state: &State<MyState>) -> Redirect {
    // https://anilist.co/api/v2/oauth/authorize?
    // client_id' => '{client_id}',
    // 'redirect_uri' => '{redirect_uri}', // http://example.com/callback
    // 'response_type' => 'code'

    const ANILIST_BASE: &str = "https://anilist.co/api/v2/oauth/authorize";
    let params = [
        ("client_id", state.client_id.as_str()),
        ("redirect_uri", "http://127.0.0.1:8000/authorized"),
        ("response_type", "code"),
    ];
    let url = Url::parse_with_params(ANILIST_BASE, &params).unwrap();

    Redirect::to(url.to_string())
}

#[get("/authorized?<code>")]
async fn authorized(code: String, state: &State<MyState>) -> Result<String, BadRequest<String>> {
    //     $response = $http->post('https://anilist.co/api/v2/oauth/token', [
    //     'form_params' => [
    //         'grant_type' => 'authorization_code',
    //         'client_id' => '{client_id}',
    //         'client_secret' => '{client_secret}',
    //         'redirect_uri' => '{redirect_uri}', // http://example.com/callback
    //         'code' => '{code}', // The Authorization code received previously
    //     ],
    //     'headers' => [
    //         'Accept' => 'application/json'
    //     ]
    // ]);

    #[derive(Debug, Deserialize)]
    #[serde(crate = "rocket::serde")]
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
        ("redirect_uri", "http://127.0.0.1:8000/authorized"),
        ("code", code.as_str()),
    ]);

    let response = state
        .client
        .post(ANILIST_BASE)
        .json(&params)
        .send()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    let body = response
        .json::<TokenResponse>()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    Ok(format!("{:#?}", body))
}

struct MyState {
    client_id: String,
    client_secret: String,
    client: reqwest::Client,
}

#[shuttle_service::main]
async fn rocket(
    #[shuttle_secrets::Secrets] secret_store: SecretStore,
) -> shuttle_service::ShuttleRocket {
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

    let state = MyState {
        client_id,
        client_secret,
        client: reqwest::Client::new(),
    };
    let rocket = rocket::build()
        .mount("/", routes![secret, login, authorized])
        .manage(state);

    Ok(rocket)
}
