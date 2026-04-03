use crate::utils::structs::MyState;
use rocket::{
    State,
    http::Status,
    response::status::Custom,
    serde::{Serialize, json::Json},
};

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
pub struct HealthChecks<'a> {
    database: &'a str,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
pub struct HealthResponse<'a> {
    status: &'a str,
    checks: HealthChecks<'a>,
}

#[get("/healthz")]
#[tracing::instrument(name = "healthz", skip(state))]
pub async fn healthz(state: &State<MyState>) -> Custom<Json<HealthResponse<'static>>> {
    let db_result = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await;

    match db_result {
        Ok(_) => Custom(
            Status::Ok,
            Json(HealthResponse {
                status: "healthy",
                checks: HealthChecks { database: "ok" },
            }),
        ),
        Err(_) => {
            error!("Health check failed for database dependency");

            Custom(
                Status::ServiceUnavailable,
                Json(HealthResponse {
                    status: "unhealthy",
                    checks: HealthChecks { database: "error" },
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::healthz;
    use crate::utils::structs::MyState;
    use rocket::{Config, http::Status, local::asynchronous::Client, routes};
    use sqlx::{Pool, Postgres};

    fn build_test_rocket(pool: Pool<Postgres>) -> rocket::Rocket<rocket::Build> {
        let figment =
            Config::figment().merge(("secret_key", "0123456789abcdef0123456789abcdef0123456789A="));

        let state = MyState {
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
            redirect_uri: "http://127.0.0.1:8000/oauth/anilist/callback".to_string(),
            context_signing_secret: "context-signing-secret".to_string(),
            user_id_hash_salt: "test-userid-hash-salt".to_string(),
            context_ttl_seconds: 300,
            state_ttl_seconds: 600,
            token_endpoint: "https://anilist.co/api/v2/oauth/token".to_string(),
            user_endpoint: "https://graphql.anilist.co".to_string(),
            client: reqwest::Client::new(),
            pool,
        };

        rocket::custom(figment)
            .mount("/", routes![healthz])
            .manage(state)
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn healthz_returns_healthy_when_database_is_available(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(pool.clone()))
            .await
            .expect("rocket client should build");

        let response = client.get("/healthz").dispatch().await;

        assert_eq!(response.status(), Status::Ok);
        let body = response
            .into_string()
            .await
            .expect("health endpoint should return body");
        assert!(body.contains("\"status\":\"healthy\""));
        assert!(body.contains("\"database\":\"ok\""));

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn healthz_returns_unhealthy_when_database_is_unavailable(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(pool.clone()))
            .await
            .expect("rocket client should build");

        pool.close().await;

        let response = client.get("/healthz").dispatch().await;

        assert_eq!(response.status(), Status::ServiceUnavailable);
        let body = response
            .into_string()
            .await
            .expect("health endpoint should return body");
        assert!(body.contains("\"status\":\"unhealthy\""));
        assert!(body.contains("\"database\":\"error\""));

        drop(client);
    }
}
