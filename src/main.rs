use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    db: PgPool,
}

#[derive(Serialize, Deserialize)]
struct User {
    id: i32,
    email: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    encrypted_vault: String,
}

#[derive(Deserialize)]
struct VaultUpdate {
    encrypted_vault: String,
}

#[derive(Serialize)]
struct VaultResponse {
    encrypted_vault: String,
}

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://user:password@localhost/passwordmanager".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            encrypted_vault TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .expect("Failed to create table");

    let state = AppState { db: pool };

    let app = Router::new()
        .route("/register", post(register))
        .route("/vault/:email", get(get_vault))
        .route("/vault/:email", put(update_vault))
        .with_state(state)
        .layer(tower_http::cors::CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<User>, StatusCode> {
    let result = sqlx::query_as::<_, (i32, String)>(
        "INSERT INTO users (email, encrypted_vault) VALUES ($1, $2) RETURNING id, email",
    )
    .bind(&payload.email)
    .bind(&payload.encrypted_vault)
    .fetch_one(&state.db)
    .await;

    match result {
        Ok((id, email)) => Ok(Json(User { id, email })),
        Err(_) => Err(StatusCode::CONFLICT),
    }
}

async fn get_vault(
    State(state): State<AppState>,
    Path(email): Path<String>,
) -> Result<Json<VaultResponse>, StatusCode> {
    let result =
        sqlx::query_as::<_, (String,)>("SELECT encrypted_vault FROM users WHERE email = $1")
            .bind(&email)
            .fetch_one(&state.db)
            .await;

    match result {
        Ok((encrypted_vault,)) => Ok(Json(VaultResponse { encrypted_vault })),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn update_vault(
    State(state): State<AppState>,
    Path(email): Path<String>,
    Json(payload): Json<VaultUpdate>,
) -> Result<StatusCode, StatusCode> {
    let result = sqlx::query("UPDATE users SET encrypted_vault = $1 WHERE email = $2")
        .bind(&payload.encrypted_vault)
        .bind(&email)
        .execute(&state.db)
        .await;

    match result {
        Ok(r) if r.rows_affected() > 0 => Ok(StatusCode::OK),
        _ => Err(StatusCode::NOT_FOUND),
    }
}
