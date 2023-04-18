#[macro_use]
extern crate rocket;
pub mod routes;
pub mod utils;

use crate::{
    routes::{authorized::authorized, login::login},
    utils::structs::MyState,
};

use anyhow::anyhow;
use shuttle_secrets::SecretStore;
use sqlx::postgres::PgPoolOptions;

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

    let database_url = if let Some(database_url) = secret_store.get("DATABASE_URL") {
        database_url
    } else {
        return Err(anyhow!("Database URL was not found").into());
    };

    let secret_key = if let Some(secret_key) = secret_store.get("SECRET_KEY") {
        secret_key
    } else {
        return Err(anyhow!("Secret Key was not found").into());
    };

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .map_err(|e| anyhow!("Failed to connect to database: {}", e))?;

    let state = MyState {
        client_id,
        client_secret,
        redirect_uri,
        client: reqwest::Client::new(),
        pool,
    };

    let figment = rocket::Config::figment().merge(("secret_key", secret_key));

    let rocket = rocket::custom(figment)
        .mount("/", routes![login, authorized])
        .manage(state);

    Ok(rocket.into())
}
