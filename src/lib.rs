//! Core library for the zcloudpass backend.
//!
//! This crate exposes the application `AppState`, helpers to ensure the
//! database schema is present, and the top-level `api` and `middleware`
//! modules used by the HTTP server.

pub mod api;
pub mod middleware;

/// Shared application state stored inside an `Arc` and attached to Axum
/// request handlers via `Extension`.
#[derive(Clone)]
pub struct AppState {
    /// Postgres connection pool used throughout the application.
    pub db: sqlx::PgPool,
}

/// Creates the `users` and `sessions` tables if they do not already exist.
///
/// This is intended to be a convenience for development and tests. It also
/// attempts to enable the `pgcrypto` extension (best-effort) and will return
/// any SQL errors encountered while creating tables.
pub async fn ensure_tables(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
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
