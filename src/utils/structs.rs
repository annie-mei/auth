use rocket_db_pools::sqlx;
use serde::Deserialize;
use sqlx::PgPool;

pub struct MyState {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub client: reqwest::Client,
    pub pool: PgPool,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TokenResponse {
    pub token_type: String,
    pub expires_in: i32,
    pub access_token: String,
    pub refresh_token: String,
}

pub struct StateToken<'r>(pub &'r str);

#[derive(Debug)]
pub enum StateTokenError {
    Missing,
    Invalid,
}
