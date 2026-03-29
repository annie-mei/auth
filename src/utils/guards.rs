use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
};

use super::structs::{StateToken, StateTokenError};
use crate::utils::functions::is_valid_state_token;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for StateToken<'r> {
    type Error = StateTokenError;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let jar = req.cookies();

        match req.query_value::<&str>("state") {
            None => Outcome::Error((Status::BadRequest, StateTokenError::Missing)),
            Some(state) => match state {
                Ok(state) => {
                    if is_valid_state_token(jar, state) {
                        Outcome::Success(StateToken(state))
                    } else {
                        Outcome::Error((Status::BadRequest, StateTokenError::Invalid))
                    }
                }
                Err(error) => {
                    info!("Failed to parse state query parameter: {error:?}");
                    Outcome::Error((Status::BadRequest, StateTokenError::Invalid))
                }
            },
        }
    }
}
