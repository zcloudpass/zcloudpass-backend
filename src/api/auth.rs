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

// password hashing & verification
use argon2::Argon2;
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

// auth extractor type
use crate::middleware::AuthUser;

// RegisterRequest is declared later with the master_password field (duplicate removed)

#[derive(Serialize)]
pub struct RegisterResponse {
    pub id: i32,
    pub email: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: Option<String>,
    pub email: String,
    pub master_password: String,
    pub encrypted_vault: Option<String>,
}

#[derive(Deserialize)]
pub struct SessionCreateRequest {
    pub email: String,
    pub master_password: String,
}

#[derive(Serialize)]
pub struct SessionCreateResponse {
    pub session_token: String,
    pub expires_at: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

pub fn router() -> Router {
    Router::new()
        .route("/register", post(register_user))
        .route("/login", post(create_session_token))
        .route("/session", post(create_session_token))
        .route("/change-password", post(change_password))
        .route("/health", get(health))
}

async fn health() -> &'static str {
    "auth ok"
}

async fn change_password(
    auth_user: AuthUser,
    Extension(state): Extension<Arc<crate::AppState>>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<StatusCode, StatusCode> {
    let pool: &PgPool = &state.db;

    // fetch existing hash for user
    let row = sqlx::query("SELECT srp_salt, srp_verifier FROM users WHERE id = $1")
        .bind(auth_user.user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            eprintln!("db error fetching user for change-password: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let (_db_salt_opt, db_hash_opt) = match row {
        Some(r) => (
            r.try_get::<Option<String>, &str>("srp_salt").ok().flatten(),
            r.try_get::<Option<String>, &str>("srp_verifier")
                .ok()
                .flatten(),
        ),
        None => (None, None),
    };

    let db_hash = match db_hash_opt {
        Some(h) => h,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // Verify current password
    let parsed = PasswordHash::new(&db_hash).map_err(|e| {
        eprintln!("invalid password hash in DB: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Argon2::default()
        .verify_password(payload.current_password.as_bytes(), &parsed)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Generate new salt & hash for new password
    let mut rng = OsRng;
    let salt = SaltString::generate(&mut rng);
    let argon2 = Argon2::default();
    let new_hash = argon2
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|e| {
            eprintln!("password hash error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .to_string();

    let res = sqlx::query("UPDATE users SET srp_salt = $1, srp_verifier = $2 WHERE id = $3")
        .bind(salt.as_str())
        .bind(new_hash)
        .bind(auth_user.user_id)
        .execute(pool)
        .await
        .map_err(|e| {
            eprintln!("db error updating password: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if res.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(StatusCode::OK)
}

async fn register_user(
    Extension(state): Extension<Arc<crate::AppState>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<AxumJson<RegisterResponse>, StatusCode> {
    let pool: &PgPool = &state.db;

    // generate salt and hash for master password
    let mut rng = OsRng;
    let salt = SaltString::generate(&mut rng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(payload.master_password.as_bytes(), &salt)
        .map_err(|e| {
            eprintln!("password hash error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .to_string();

    let res = sqlx::query(
        r#"
        INSERT INTO users (username, email, srp_salt, srp_verifier, encrypted_vault, created_at)
        VALUES ($1, $2, $3, $4, $5, now())
        RETURNING id, email
        "#,
    )
    .bind(payload.username)
    .bind(&payload.email)
    .bind(salt.as_str())
    .bind(password_hash)
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

async fn create_session_token(
    Extension(state): Extension<Arc<crate::AppState>>,
    Json(payload): Json<SessionCreateRequest>,
) -> Result<AxumJson<SessionCreateResponse>, StatusCode> {
    let pool: &PgPool = &state.db;

    // fetch user and the stored password hash
    let user_row = sqlx::query("SELECT id, srp_verifier FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(pool)
        .await
        .map_err(|e| {
            eprintln!("db lookup error: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let (user_id, db_hash) = match user_row {
        Some(row) => {
            let id = row
                .try_get::<i32, &str>("id")
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let hash = row
                .try_get::<Option<String>, &str>("srp_verifier")
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
                .ok_or(StatusCode::UNAUTHORIZED)?;
            (id, hash)
        }
        None => return Err(StatusCode::NOT_FOUND),
    };

    // verify provided master password against stored hash
    let parsed = PasswordHash::new(&db_hash).map_err(|e| {
        eprintln!("invalid password hash in DB: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Argon2::default()
        .verify_password(payload.master_password.as_bytes(), &parsed)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // password verified, create session
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
