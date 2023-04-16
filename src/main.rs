#[macro_use]
extern crate rocket;
pub mod routes;
pub mod utils;

use crate::{
    routes::{authorized::authorized, login::login},
    utils::structs::{AnnieMei, MyState},
};

use anyhow::anyhow;
use rocket_db_pools::Database;
use shuttle_secrets::SecretStore;

#[shuttle_runtime::main]
async fn rocket(
    #[shuttle_secrets::Secrets] secret_store: SecretStore,
) -> shuttle_rocket::ShuttleRocket {
    let sentry_dsn = if let Some(client_id) = secret_store.get("SENTRY_DSN") {
        client_id
    } else {
        return Err(anyhow!("Sentry DSN was not found").into());
    };

    let _guard = sentry::init((
        sentry_dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            traces_sample_rate: 1.0,
            enable_profiling: true,
            profiles_sample_rate: 1.0,
            ..Default::default()
        },
    ));

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
        .attach(AnnieMei::init())
        .mount("/", routes![login, authorized])
        .manage(state);

    Ok(rocket.into())
}
