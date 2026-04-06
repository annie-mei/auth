use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
};

use super::structs::{MyState, StateToken, StateTokenError};
use crate::utils::functions::{SessionConsumeError, consume_oauth_session};
use crate::utils::observability::configure_oauth_scope;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for StateToken {
    type Error = StateTokenError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let state_val = match req.query_value::<&str>("state") {
            None => return Outcome::Error((Status::BadRequest, StateTokenError::Missing)),
            Some(Err(_)) => {
                info!("Failed to parse state query parameter");
                return Outcome::Error((Status::BadRequest, StateTokenError::Invalid));
            }
            Some(Ok(s)) => s,
        };

        let pool = match req.rocket().state::<MyState>() {
            Some(s) => &s.pool,
            None => {
                error!("MyState not managed -- cannot validate OAuth session");
                return Outcome::Error((Status::InternalServerError, StateTokenError::Internal));
            }
        };

        match consume_oauth_session(state_val, pool).await {
            Ok(session) => Outcome::Success(StateToken(session.discord_user_id)),
            Err(SessionConsumeError::NotFound) => {
                info!("State validation failed: session not found");
                Outcome::Error((Status::BadRequest, StateTokenError::Invalid))
            }
            Err(SessionConsumeError::Expired) => {
                info!("State validation failed: session expired");
                Outcome::Error((Status::BadRequest, StateTokenError::Expired))
            }
            Err(SessionConsumeError::AlreadyUsed) => {
                info!("State validation failed: replay attempt detected");
                sentry::with_scope(
                    |scope| {
                        configure_oauth_scope(scope, "oauth.state.consume_session", None);
                    },
                    || {
                        sentry::capture_message(
                            "OAuth state replay attempt detected",
                            sentry::Level::Warning,
                        )
                    },
                );
                Outcome::Error((Status::BadRequest, StateTokenError::Replayed))
            }
            Err(SessionConsumeError::Db(e)) => {
                sentry::with_scope(
                    |scope| {
                        configure_oauth_scope(scope, "oauth.state.consume_session", None);
                    },
                    || sentry::capture_error(&e),
                );
                error!("Database error during state validation");
                Outcome::Error((Status::InternalServerError, StateTokenError::Internal))
            }
        }
    }
}
