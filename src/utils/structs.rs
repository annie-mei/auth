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
pub struct TokenResponse {
    pub access_token: String,
}

#[derive(Deserialize)]
pub struct ViewerResponse {
    pub data: ViewerData,
}

#[derive(Deserialize)]
pub struct ViewerData {
    #[serde(rename = "Viewer")]
    pub viewer: Viewer,
}

#[derive(Deserialize)]
pub struct Viewer {
    pub id: i64,
}

pub struct StateToken<'r>(pub &'r str);

#[derive(Debug)]
pub enum StateTokenError {
    Missing,
    Invalid,
}
