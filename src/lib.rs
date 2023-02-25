#[macro_use]
extern crate rocket;

use anyhow::anyhow;
use rocket::response::status::BadRequest;
use rocket::State;
use shuttle_secrets::SecretStore;

#[get("/secret")]
async fn secret(state: &State<MyState>) -> Result<String, BadRequest<String>> {
    Ok(state.secret.clone())
}

struct MyState {
    secret: String,
}

#[shuttle_service::main]
async fn rocket(
    #[shuttle_secrets::Secrets] secret_store: SecretStore,
) -> shuttle_service::ShuttleRocket {
    // get secret defined in `Secrets.toml` file.
    let secret = if let Some(secret) = secret_store.get("ANILIST_CLIENT_ID") {
        secret
    } else {
        return Err(anyhow!("secret was not found").into());
    };

    let state = MyState { secret };
    let rocket = rocket::build().mount("/", routes![secret]).manage(state);

    Ok(rocket)
}
