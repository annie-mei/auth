use rocket_db_pools::{sqlx, Database};
use serde::Deserialize;

#[derive(Database)]
#[database("annie-mei")]
pub struct AnnieMei(sqlx::PgPool);

pub struct MyState {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TokenResponse {
    pub token_type: String,
    pub expires_in: i32,
    pub access_token: String,
    pub refresh_token: String,
}
