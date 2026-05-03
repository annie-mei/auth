use std::fmt;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::PgPool;

pub struct MyState {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub context_signing_secret: String,
    pub user_id_hash_salt: String,
    pub context_ttl_seconds: i64,
    pub state_ttl_seconds: i64,
    pub token_endpoint: String,
    pub user_endpoint: String,
    pub client: reqwest::Client,
    pub pool: PgPool,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct OAuthContextPayload {
    pub v: u8,
    pub discord_user_id: String,
    pub guild_id: Option<String>,
    pub interaction_id: String,
    pub nonce: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub token_type: Option<String>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_in", &self.expires_in)
            .field("token_type", &self.token_type)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenErrorResponse {
    pub error: Option<String>,
    pub message: Option<String>,
    pub error_description: Option<String>,
}

#[derive(sqlx::FromRow)]
pub struct OAuthCredential {
    pub discord_user_id: String,
    pub anilist_id: i64,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub token_updated_at: DateTime<Utc>,
    pub relink_required_at: Option<DateTime<Utc>>,
    pub relink_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl fmt::Debug for OAuthCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthCredential")
            .field("discord_user_id", &self.discord_user_id)
            .field("anilist_id", &self.anilist_id)
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_expires_at", &self.token_expires_at)
            .field("token_updated_at", &self.token_updated_at)
            .field("relink_required_at", &self.relink_required_at)
            .field("relink_reason", &self.relink_reason)
            .field("created_at", &self.created_at)
            .finish()
    }
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
    use super::{OAuthContextPayload, TokenResponse};

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

    #[test]
    fn oauth_context_payload_deserializes_v1_shape() {
        let json = r#"{
            "v": 1,
            "discord_user_id": "123456789012345678",
            "guild_id": "987654321098765432",
            "interaction_id": "12222333344445555",
            "nonce": "bM0XvTa5yT4K0z2yPxtA3A",
            "iat": 1711500000,
            "exp": 1711500300
        }"#;
        let payload: OAuthContextPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.v, 1);
        assert_eq!(payload.discord_user_id, "123456789012345678");
        assert_eq!(payload.guild_id.as_deref(), Some("987654321098765432"));
    }

    #[test]
    fn token_response_debug_redacts_tokens() {
        let token_response = TokenResponse {
            access_token: "access_secret".to_string(),
            refresh_token: Some("refresh_secret".to_string()),
            expires_in: Some(3600),
            token_type: Some("Bearer".to_string()),
        };

        let debug = format!("{token_response:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("access_secret"));
        assert!(!debug.contains("refresh_secret"));
    }

    #[test]
    fn oauth_credential_debug_redacts_tokens() {
        let now = chrono::Utc::now();
        let credential = super::OAuthCredential {
            discord_user_id: "123456789012345678".to_string(),
            anilist_id: 42,
            access_token: "access_secret".to_string(),
            refresh_token: Some("refresh_secret".to_string()),
            token_expires_at: Some(now),
            token_updated_at: now,
            relink_required_at: None,
            relink_reason: None,
            created_at: now,
        };

        let debug = format!("{credential:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("access_secret"));
        assert!(!debug.contains("refresh_secret"));
    }
}
