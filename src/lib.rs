pub mod api;
pub mod middleware;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
}

/// Creates the `users` and `sessions` tables if they do not already exist.
/// Also attempts to enable the `pgcrypto` extension (best-effort).
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
