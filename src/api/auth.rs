use axum::{
    Router,
    extract::{Extension, Json},
    http::StatusCode,
    response::Json as AxumJson,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: Option<String>,
    pub email: String,

    pub srp_salt: Option<String>,
    pub srp_verifier: Option<String>,

    pub encrypted_vault: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: i32,
    pub email: String,
}

#[derive(Deserialize)]
pub struct SessionCreateRequest {
    pub email: String,

    pub placeholder: Option<String>,
}

#[derive(Serialize)]
pub struct SessionCreateResponse {
    pub session_token: String,
    pub expires_at: String,
}

pub fn router() -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/session", post(create_session))
        .route("/health", get(health))
}

async fn health() -> &'static str {
    "auth ok"
}

async fn register(
    Extension(state): Extension<Arc<crate::AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<AxumJson<RegisterResponse>, StatusCode> {
    let pool: &PgPool = &state.db;

    let res = sqlx::query(
        r#"
        INSERT INTO users (username, email, srp_salt, srp_verifier, encrypted_vault, created_at)
        VALUES ($1, $2, $3, $4, $5, now())
        RETURNING id, email
        "#,
    )
    .bind(payload.username)
    .bind(&payload.email)
    .bind(payload.srp_salt)
    .bind(payload.srp_verifier)
    .bind(payload.encrypted_vault)
    .fetch_one(pool)
    .await;

    match res {
        Ok(row) => {
            let id: i32 = row.try_get("id").unwrap_or_default();
            let email: String = row.try_get("email").unwrap_or_default();
            Ok(AxumJson(RegisterResponse { id, email }))
        }
        Err(e) => {
            eprintln!("register error: {:?}", e);
            Err(StatusCode::CONFLICT)
        }
    }
}

async fn create_session(
    Extension(state): Extension<Arc<crate::AppState>>,
    Json(payload): Json<SessionCreateRequest>,
) -> Result<AxumJson<SessionCreateResponse>, StatusCode> {
    let pool: &PgPool = &state.db;

    let user_row = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            eprintln!("db lookup error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let user_id = match user_row {
        Some(row) => row
            .try_get::<i32, &str>("id")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // generate a server-side session token (UUID v4) and persist it
    let session_token = Uuid::new_v4().to_string();

    let insert_q = sqlx::query(
        r#"
        INSERT INTO sessions (user_id, session_token, created_at, expires_at, last_activity)
        VALUES ($1, $2, now(), (now() + interval '1 hour'), now())
        RETURNING session_token, (expires_at)::text AS expires_at_text
        "#,
    )
    .bind(user_id)
    .bind(&session_token);

    let inserted = insert_q.fetch_one(pool).await.map_err(|e| {
        eprintln!("session insert error: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let token: String = inserted
        .try_get("session_token")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let expires_at: String = inserted
        .try_get("expires_at_text")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(AxumJson(SessionCreateResponse {
        session_token: token,
        expires_at,
    }))
}
