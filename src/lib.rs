#[macro_use]
extern crate rocket;

use anyhow::anyhow;
use rocket::{
    response::{status::BadRequest, Redirect},
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

struct MyState {
    client_id: String,
}

#[shuttle_service::main]
async fn rocket(
    #[shuttle_secrets::Secrets] secret_store: SecretStore,
) -> shuttle_service::ShuttleRocket {
    // get secret defined in `Secrets.toml` file.
    let client_id = if let Some(client_id) = secret_store.get("ANILIST_CLIENT_ID") {
        client_id
    } else {
        return Err(anyhow!("secret was not found").into());
    };

    let state = MyState { client_id };
    let rocket = rocket::build()
        .mount("/", routes![secret, login])
        .manage(state);

    Ok(rocket)
}
