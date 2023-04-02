#[macro_use]
extern crate rocket;

use std::collections::HashMap;

use anyhow::anyhow;
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use rocket::{
    log::private::info,
    response::{status::BadRequest, Redirect},
    State,
};
use serde::Deserialize;
use serde_json::json;
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
    let access_token = response
        .json::<TokenResponse>()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?
        .access_token;

    info!("Fetching User data ...");

    info!("User data fetched successfully! ...");

    match fetch_viewer_id(state.client.clone(), access_token).await {
        Ok(id) => {
            info!("User ID: {:#?}", id);
            Ok("success".to_string())
        }
        Err(e) => {
            info!("Error: {:#?}", e);
            Err(e)
        }
    }
}

async fn fetch_viewer_id(
    client: reqwest::Client,
    access_token: String,
) -> Result<i64, BadRequest<String>> {
    const USER_QUERY: &str = "
    query {
        Viewer {
            id
        }
    }
    ";
    const ANILIST_USER_BASE: &str = "https://graphql.anilist.co";

    let authorization_param = format!("Bearer {}", access_token);

    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, authorization_param.parse().unwrap());
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    headers.insert(ACCEPT, "application/json".parse().unwrap());

    let viewer_response = client
        .post(ANILIST_USER_BASE)
        .headers(headers)
        .body(json!({ "query": USER_QUERY }).to_string())
        .send()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    let viewer_response = viewer_response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    viewer_response["data"]["Viewer"]["id"]
        .as_i64()
        .ok_or_else(|| BadRequest(Some("Failed to parse viewer id".to_string())))
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
