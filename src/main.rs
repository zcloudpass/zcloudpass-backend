mod api;

use axum::{Extension, Router, routing::get};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct AppState {
    db: sqlx::PgPool,
}

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://user:password@localhost:5432/zcloudpass".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");

    ensure_tables(&pool).await.expect("Failed to ensure tables");

    let app_state = AppState { db: pool.clone() };
    let shared_state = Arc::new(app_state);

    let app = Router::new()
        .merge(api::router())
        .route("/health", get(|| async { "zcloudpass: ok" }))
        .layer(CorsLayer::permissive())
        .layer(Extension(shared_state));

    let bind = std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    println!("Server running on http://{}", bind);

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .expect("Failed to bind TCP listener");
    axum::serve(listener, app).await.unwrap();
}

async fn ensure_tables(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    // Try to create the pgcrypto extension separately.
    // Creation requires superuser privileges; if it fails, log a warning and continue.
    match sqlx::query("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
        .execute(pool)
        .await
    {
        Ok(_) => println!("pgcrypto extension ensured"),
        Err(e) => eprintln!(
            "notice: could not create pgcrypto extension (continuing): {:?}. \
             If you need pgcrypto functionality, create the extension as a superuser.",
            e
        ),
    }

    // Create users table (single statement)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255),
            email VARCHAR(255) UNIQUE NOT NULL,
            srp_salt TEXT,
            srp_verifier TEXT,
            encrypted_vault TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            account_status VARCHAR(20) DEFAULT 'active'
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create sessions table (single statement)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sessions (
            id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(id) ON DELETE CASCADE,
            session_token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}
