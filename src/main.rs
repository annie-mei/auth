#[macro_use]
extern crate rocket;
pub mod routes;
pub mod utils;

use crate::{
    routes::{authorized::authorized, catchers::not_found, healthz::healthz, start::start},
    utils::{
        consts::{ANILIST_TOKEN, ANILIST_USER_BASE},
        structs::MyState,
    },
};
use rocket::fs::{FileServer, relative};

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;
use tracing_subscriber::prelude::*;

const DEFAULT_CONTEXT_TTL_SECONDS: i64 = 300;
const DEFAULT_STATE_TTL_SECONDS: i64 = 300;

struct AppConfig {
    sentry_dsn: Option<String>,
    sentry_environment: Option<String>,
    sentry_traces_sample_rate: f32,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    context_signing_secret: String,
    user_id_hash_salt: String,
    context_ttl_seconds: i64,
    state_ttl_seconds: i64,
    database_url: String,
    rocket_secret_key: String,
}

impl AppConfig {
    fn from_env() -> Result<Self> {
        let _ = dotenvy::dotenv();

        let (sentry_traces_sample_rate, sentry_traces_sample_rate_invalid) =
            match optional_env("SENTRY_TRACES_SAMPLE_RATE") {
                Some(raw) => match raw.parse::<f32>() {
                    Ok(rate) if rate.is_finite() => (rate.clamp(0.0, 1.0), None),
                    _ => (0.0, Some(raw)),
                },
                None => (0.0, None),
            };

        if let Some(invalid_value) = sentry_traces_sample_rate_invalid {
            eprintln!("Invalid SENTRY_TRACES_SAMPLE_RATE={invalid_value}; defaulting to 0.0");
        }

        Ok(Self {
            sentry_dsn: optional_env("SENTRY_DSN"),
            sentry_environment: optional_env("SENTRY_ENVIRONMENT"),
            sentry_traces_sample_rate,
            client_id: required_env("ANILIST_CLIENT_ID")?,
            client_secret: required_env("ANILIST_CLIENT_SECRET")?,
            redirect_uri: required_env("ANILIST_REDIRECT_URI")?,
            context_signing_secret: required_env("OAUTH_CONTEXT_SIGNING_SECRET")?,
            user_id_hash_salt: required_env("USERID_HASH_SALT")?,
            context_ttl_seconds: optional_positive_i64_env("OAUTH_CONTEXT_TTL_SECONDS")?
                .unwrap_or(DEFAULT_CONTEXT_TTL_SECONDS),
            state_ttl_seconds: optional_positive_i64_env("OAUTH_STATE_TTL_SECONDS")?
                .unwrap_or(DEFAULT_STATE_TTL_SECONDS),
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
    let value = env::var(key).with_context(|| format!("{key} was not found"))?;

    non_empty_env_value(value).with_context(|| format!("{key} was empty"))
}

fn optional_positive_i64_env(key: &str) -> Result<Option<i64>> {
    let Some(value) = optional_env(key) else {
        return Ok(None);
    };

    let parsed = value
        .parse::<i64>()
        .with_context(|| format!("{key} must be a positive integer"))?;

    (parsed > 0)
        .then_some(parsed)
        .with_context(|| format!("{key} must be a positive integer"))
        .map(Some)
}

fn init_sentry(
    dsn: &str,
    environment: Option<String>,
    traces_sample_rate: f32,
) -> sentry::ClientInitGuard {
    use crate::utils::observability::redact_url_credentials;

    sentry::init((
        dsn,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            environment: environment.map(Into::into),
            traces_sample_rate,
            enable_logs: true,
            before_send: Some(Arc::new(|mut event| {
                for exception in event.exception.values.iter_mut() {
                    if let Some(ref mut value) = exception.value {
                        *value = redact_url_credentials(value);
                    }
                }
                if let Some(ref mut message) = event.message {
                    *message = redact_url_credentials(message);
                }
                for breadcrumb in event.breadcrumbs.values.iter_mut() {
                    if let Some(ref mut message) = breadcrumb.message {
                        *message = redact_url_credentials(message);
                    }
                }
                Some(event)
            })),
            before_send_log: Some(Arc::new(|mut log| {
                log.body = redact_url_credentials(&log.body);
                Some(log)
            })),
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

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("Failed to run database migrations")?;

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
        context_signing_secret: config.context_signing_secret.clone(),
        user_id_hash_salt: config.user_id_hash_salt.clone(),
        context_ttl_seconds: config.context_ttl_seconds,
        state_ttl_seconds: config.state_ttl_seconds,
        token_endpoint: ANILIST_TOKEN.to_string(),
        user_endpoint: ANILIST_USER_BASE.to_string(),
        client,
        pool,
    };

    let figment = rocket::Config::figment().merge(("secret_key", config.rocket_secret_key.clone()));

    Ok(rocket::custom(figment)
        .mount("/", routes![healthz, start, authorized])
        .mount("/static", FileServer::from(relative!("static")))
        .register("/", catchers![not_found])
        .manage(state))
}

#[rocket::main]
async fn main() -> Result<()> {
    let config = AppConfig::from_env()?;
    let _sentry = config.sentry_dsn.as_deref().map(|dsn| {
        init_sentry(
            dsn,
            config.sentry_environment.clone(),
            config.sentry_traces_sample_rate,
        )
    });

    tracing_subscriber::registry()
        .with(sentry::integrations::tracing::layer())
        .init();

    if config.sentry_dsn.is_none() {
        eprintln!("SENTRY_DSN not set; Sentry is disabled");
    } else if config.sentry_traces_sample_rate > 0.0 {
        info!(
            "Sentry trace sampling enabled (sample_rate={})",
            config.sentry_traces_sample_rate
        );
    }

    build_rocket(&config).await?.launch().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{non_empty_env_value, optional_positive_i64_env, required_env};
    use std::env;

    #[test]
    fn non_empty_env_value_rejects_blank_strings() {
        assert_eq!(non_empty_env_value(String::new()), None);
        assert_eq!(non_empty_env_value("   ".to_string()), None);
        assert_eq!(
            non_empty_env_value("dsn".to_string()),
            Some("dsn".to_string())
        );
    }

    #[test]
    fn required_env_rejects_blank_values() {
        let key = "ANNIE_MEI_AUTH_REQUIRED_ENV_TEST";

        unsafe { env::set_var(key, "   ") };
        let error = required_env(key).expect_err("blank env vars should fail validation");
        assert!(error.to_string().contains("was empty"));

        unsafe { env::set_var(key, "value") };
        let value = required_env(key).expect("non-empty env vars should pass validation");
        assert_eq!(value, "value");

        unsafe { env::remove_var(key) };
    }

    #[test]
    fn optional_positive_i64_env_rejects_zero() {
        let key = "ANNIE_MEI_AUTH_OPTIONAL_INT_TEST";

        unsafe { env::set_var(key, "0") };
        let error = optional_positive_i64_env(key).expect_err("zero should fail validation");
        assert!(error.to_string().contains("positive integer"));

        unsafe { env::remove_var(key) };
    }
}
