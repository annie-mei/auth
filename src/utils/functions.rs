use crate::{utils::consts::ANILIST_USER_BASE, AnnieMei};
use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use rocket::response::status::BadRequest;
use rocket_db_pools::Connection;
use serde_json::json;

pub async fn fetch_viewer_id(
    client: reqwest::Client,
    access_token: String,
) -> Result<i64, BadRequest<String>> {
    const USER_QUERY: &str = "
    query {
        Viewer {
            id
        }
    }
    ";

    let authorization_param = format!("Bearer {}", access_token);

    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, authorization_param.parse().unwrap());
    headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
    headers.insert(ACCEPT, "application/json".parse().unwrap());

    let viewer_response = client
        .post(ANILIST_USER_BASE)
        .headers(headers)
        .body(json!({ "query": USER_QUERY }).to_string())
        .send()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    let viewer_response = viewer_response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| BadRequest(Some(e.to_string())))?;

    viewer_response["data"]["Viewer"]["id"]
        .as_i64()
        .ok_or_else(|| BadRequest(Some("Failed to parse viewer id".to_string())))
}

pub async fn save_access_token(
    access_token: String,
    anilist_id: i64,
    mut db: Connection<AnnieMei>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    info!("Saving access token ...");
    sqlx::query("UPDATE users SET access_token=$1 WHERE anilist_id=$2")
        .bind(access_token)
        .bind(anilist_id)
        .execute(&mut *db)
        .await
}
