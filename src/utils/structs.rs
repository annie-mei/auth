use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

pub struct MyState {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub bot_auth_secret: String,
    pub token_endpoint: String,
    pub user_endpoint: String,
    pub client: reqwest::Client,
    pub pool: PgPool,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub token_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenErrorResponse {
    pub error: Option<String>,
    pub message: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CallbackResponse {
    pub status: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct OAuthCredential {
    pub discord_user_id: String,
    pub anilist_id: i64,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub token_updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct OAuthSession {
    pub state: String,
    pub discord_user_id: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
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

/// Carries the Discord user ID recovered from the validated OAuth session.
pub struct StateToken(pub String);

#[derive(Debug)]
pub enum StateTokenError {
    Missing,
    Invalid,
    Expired,
    Replayed,
    Internal,
}

#[cfg(test)]
mod tests {
    use super::TokenResponse;

    #[test]
    fn token_response_deserializes_full_payload() {
        let json = r#"{
            "access_token": "tok_abc",
            "refresh_token": "ref_xyz",
            "expires_in": 3600,
            "token_type": "Bearer"
        }"#;
        let r: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.access_token, "tok_abc");
        assert_eq!(r.refresh_token.as_deref(), Some("ref_xyz"));
        assert_eq!(r.expires_in, Some(3600));
        assert_eq!(r.token_type.as_deref(), Some("Bearer"));
    }

    #[test]
    fn token_response_deserializes_access_token_only() {
        let json = r#"{"access_token": "tok_abc"}"#;
        let r: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(r.access_token, "tok_abc");
        assert!(r.refresh_token.is_none());
        assert!(r.expires_in.is_none());
        assert!(r.token_type.is_none());
    }
}
