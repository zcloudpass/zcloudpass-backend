use axum::{
    Router,
    extract::{Extension, Path},
    http::StatusCode,
    response::Json,
    routing::{get, put},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;

#[derive(Serialize)]
pub struct VaultResponse {
    pub encrypted_vault: Option<String>,
}

#[derive(Deserialize)]
pub struct VaultUpdate {
    pub encrypted_vault: String,
}

pub fn router() -> Router {
    Router::new()
        .route("/:email", get(get_vault))
        .route("/:email", put(update_vault))
}

async fn get_vault(
    Extension(state): Extension<Arc<crate::AppState>>,
    Path(email): Path<String>,
) -> Result<Json<VaultResponse>, StatusCode> {
    let pool: &PgPool = &state.db;

    let row = sqlx::query("SELECT encrypted_vault FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            eprintln!("vault get db error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let encrypted_vault = row.and_then(|r| {
        r.try_get::<Option<String>, &str>("encrypted_vault")
            .ok()
            .flatten()
    });

    Ok(Json(VaultResponse { encrypted_vault }))
}

async fn update_vault(
    Extension(state): Extension<Arc<crate::AppState>>,
    Path(email): Path<String>,
    axum::Json(payload): axum::Json<VaultUpdate>,
) -> Result<StatusCode, StatusCode> {
    let pool: &PgPool = &state.db;

    let res =
        sqlx::query("UPDATE users SET encrypted_vault = $1, last_login = now() WHERE email = $2")
            .bind(&payload.encrypted_vault)
            .bind(&email)
            .execute(pool)
            .await
            .map_err(|e| {
                eprintln!("vault update db error: {:?}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    if res.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::OK)
}
