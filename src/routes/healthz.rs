use crate::utils::structs::MyState;
use rocket::{
    State,
    http::Status,
    response::status::Custom,
    serde::{Serialize, json::Json},
    tokio::time::{Duration, timeout},
};

const DATABASE_CHECK_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
pub struct HealthServices<'a> {
    database: &'a str,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
pub struct HealthResponse<'a> {
    status: &'a str,
    version: &'a str,
    services: HealthServices<'a>,
}

#[tracing::instrument(name = "health.database", skip(pool))]
async fn check_database(pool: &sqlx::PgPool) -> bool {
    let db_result = timeout(
        DATABASE_CHECK_TIMEOUT,
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(pool),
    )
    .await;

    match db_result {
        Ok(Ok(_)) => true,
        Ok(Err(error)) => {
            tracing::error!(error = %error, "Health check failed for database dependency");
            false
        }
        Err(_) => {
            tracing::error!("Health check timed out waiting for database dependency");
            false
        }
    }
}

#[tracing::instrument(name = "health.response", skip_all)]
fn build_health_response(database_ok: Option<bool>) -> Custom<Json<HealthResponse<'static>>> {
    let healthy = database_ok.unwrap_or(true);
    let status = if healthy {
        Status::Ok
    } else {
        Status::ServiceUnavailable
    };

    let database_status = match database_ok {
        Some(true) => "up",
        Some(false) => "down",
        None => "not_checked",
    };

    Custom(
        status,
        Json(HealthResponse {
            status: if healthy { "healthy" } else { "unhealthy" },
            version: VERSION,
            services: HealthServices {
                database: database_status,
            },
        }),
    )
}

#[get("/healthz")]
#[tracing::instrument(name = "healthz")]
pub async fn healthz() -> Custom<Json<HealthResponse<'static>>> {
    build_health_response(None)
}

#[get("/readyz")]
#[tracing::instrument(name = "readyz", skip(state))]
pub async fn readyz(state: &State<MyState>) -> Custom<Json<HealthResponse<'static>>> {
    let database_ok = check_database(&state.pool).await;

    build_health_response(Some(database_ok))
}

#[cfg(test)]
mod tests {
    use super::{VERSION, build_health_response, healthz, readyz};
    use crate::utils::structs::MyState;
    use rocket::{Config, http::Status, local::asynchronous::Client, routes};
    use serde_json::Value;
    use sqlx::{Pool, Postgres};

    fn build_test_state(pool: Pool<Postgres>) -> MyState {
        MyState {
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
        }
    }

    fn test_figment() -> rocket::figment::Figment {
        Config::figment().merge(("secret_key", "0123456789abcdef0123456789abcdef0123456789A="))
    }

    fn build_healthz_rocket() -> rocket::Rocket<rocket::Build> {
        rocket::custom(test_figment()).mount("/", routes![healthz])
    }

    fn build_test_rocket(pool: Pool<Postgres>) -> rocket::Rocket<rocket::Build> {
        rocket::custom(test_figment())
            .mount("/", routes![healthz, readyz])
            .manage(build_test_state(pool))
    }

    async fn response_json(response: rocket::local::asynchronous::LocalResponse<'_>) -> Value {
        let body = response
            .into_string()
            .await
            .expect("health endpoint should return body");

        serde_json::from_str(&body).expect("health endpoint should return JSON")
    }

    #[test]
    fn health_response_reports_process_liveness_without_dependency_checks() {
        let response = build_health_response(None);

        assert_eq!(response.0, Status::Ok);
        assert_eq!(response.1.status, "healthy");
        assert_eq!(response.1.version, VERSION);
        assert_eq!(response.1.services.database, "not_checked");
    }

    #[test]
    fn ready_response_reports_healthy_when_database_is_up() {
        let response = build_health_response(Some(true));

        assert_eq!(response.0, Status::Ok);
        assert_eq!(response.1.status, "healthy");
        assert_eq!(response.1.version, VERSION);
        assert_eq!(response.1.services.database, "up");
    }

    #[test]
    fn ready_response_reports_unhealthy_when_database_is_down() {
        let response = build_health_response(Some(false));

        assert_eq!(response.0, Status::ServiceUnavailable);
        assert_eq!(response.1.status, "unhealthy");
        assert_eq!(response.1.version, VERSION);
        assert_eq!(response.1.services.database, "down");
    }

    #[test]
    fn healthz_returns_liveness_shape() {
        rocket::async_test(async {
            let client = Client::tracked(build_healthz_rocket())
                .await
                .expect("rocket client should build");

            let response = client.get("/healthz").dispatch().await;

            assert_eq!(response.status(), Status::Ok);
            let body = response_json(response).await;
            assert_eq!(body["status"], "healthy");
            assert_eq!(body["version"], VERSION);
            assert_eq!(body["services"]["database"], "not_checked");
        });
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn readyz_returns_healthy_when_database_is_available(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(pool.clone()))
            .await
            .expect("rocket client should build");

        let response = client.get("/readyz").dispatch().await;

        assert_eq!(response.status(), Status::Ok);
        let body = response_json(response).await;
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["version"], VERSION);
        assert_eq!(body["services"]["database"], "up");

        drop(client);
        pool.close().await;
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn readyz_returns_unhealthy_when_database_is_unavailable(pool: Pool<Postgres>) {
        let client = Client::tracked(build_test_rocket(pool.clone()))
            .await
            .expect("rocket client should build");

        pool.close().await;

        let response = client.get("/readyz").dispatch().await;

        assert_eq!(response.status(), Status::ServiceUnavailable);
        let body = response_json(response).await;
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["version"], VERSION);
        assert_eq!(body["services"]["database"], "down");

        drop(client);
    }
}
