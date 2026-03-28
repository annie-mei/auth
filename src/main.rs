#[macro_use]
extern crate rocket;
pub mod routes;
pub mod utils;

use crate::{
    routes::{authorized::authorized, login::login},
    utils::structs::MyState,
};

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use std::env;

struct AppConfig {
    sentry_dsn: Option<String>,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    database_url: String,
    rocket_secret_key: String,
}

impl AppConfig {
    fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();

        Ok(Self {
            sentry_dsn: optional_env("SENTRY_DSN"),
            client_id: required_env("ANILIST_CLIENT_ID")?,
            client_secret: required_env("ANILIST_SECRET")?,
            redirect_uri: required_env("REDIRECT_URL")?,
            database_url: required_env("DATABASE_URL")?,
            rocket_secret_key: required_env("ROCKET_SECRET_KEY")?,
        })
    }
}

fn optional_env(key: &str) -> Option<String> {
    env::var(key).ok().and_then(non_empty_env_value)
}

fn non_empty_env_value(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn required_env(key: &str) -> Result<String> {
    env::var(key).with_context(|| format!("{key} was not found"))
}

fn init_sentry(dsn: &str) -> sentry::ClientInitGuard {
    sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            ..Default::default()
        },
    ))
}

async fn build_rocket(config: &AppConfig) -> Result<rocket::Rocket<rocket::Build>> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .context("Failed to connect to the database")?;

    let client = reqwest::Client::builder()
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()
        .context("Failed to build HTTP client")?;

    let state = MyState {
        client_id: config.client_id.clone(),
        client_secret: config.client_secret.clone(),
        redirect_uri: config.redirect_uri.clone(),
        client,
        pool,
    };

    let figment = rocket::Config::figment().merge(("secret_key", config.rocket_secret_key.clone()));

    Ok(rocket::custom(figment)
        .mount("/", routes![login, authorized])
        .manage(state))
}

#[rocket::main]
async fn main() -> Result<()> {
    let config = AppConfig::from_env()?;
    let _sentry = config.sentry_dsn.as_deref().map(init_sentry);

    if config.sentry_dsn.is_none() {
        info!("SENTRY_DSN not set; Sentry is disabled");
    }

    build_rocket(&config).await?.launch().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::non_empty_env_value;

    #[test]
    fn non_empty_env_value_rejects_blank_strings() {
        assert_eq!(non_empty_env_value(String::new()), None);
        assert_eq!(non_empty_env_value("   ".to_string()), None);
        assert_eq!(
            non_empty_env_value("dsn".to_string()),
            Some("dsn".to_string())
        );
    }
}
