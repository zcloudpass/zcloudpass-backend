//! Integration tests for the zcloudpass-backend API.
//!
//! These tests require a running Postgres instance.
//! Set `DATABASE_URL` to point to a **test** database before running:
//!
//!   DATABASE_URL="postgres://user:password@localhost:5432/zcloudpass_test" cargo test --test integration

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Extension, Router};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use zcloudpass_backend::{AppState, api};

// ─── Test helpers ───────────────────────────────────────────────────────────

/// Builds the full application router backed by a real Postgres pool.
/// Truncates all data before each test group for isolation.
async fn setup() -> (Router, PgPool) {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://user:password@localhost:5432/zcloudpass_test".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database — is DATABASE_URL set?");

    zcloudpass_backend::ensure_tables(&pool)
        .await
        .expect("Failed to ensure tables");

    // Clean slate
    sqlx::query("TRUNCATE TABLE sessions, users RESTART IDENTITY CASCADE")
        .execute(&pool)
        .await
        .expect("Failed to truncate tables");

    let state = Arc::new(AppState { db: pool.clone() });

    let app = Router::new()
        .merge(api::router())
        .route("/health", get(|| async { "zcloudpass: ok" }))
        .layer(CorsLayer::permissive())
        .layer(Extension(state));

    (app, pool)
}

/// Helper: send a JSON request and return (status, body as serde_json::Value).
async fn json_request(
    app: Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    bearer_token: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);

    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }

    if let Some(token) = bearer_token {
        builder = builder.header("authorization", format!("Bearer {}", token));
    }

    let req_body = match body {
        Some(v) => Body::from(serde_json::to_vec(&v).unwrap()),
        None => Body::empty(),
    };

    let response = app.oneshot(builder.body(req_body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();

    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).to_string()))
    };

    (status, value)
}

/// Register a user and return the response JSON.
async fn register(app: Router, email: &str, password: &str) -> (StatusCode, Value) {
    json_request(
        app,
        "POST",
        "/api/v1/auth/register",
        Some(json!({
            "email": email,
            "master_password": password
        })),
        None,
    )
    .await
}

/// Login and return the session token.
async fn login(app: Router, email: &str, password: &str) -> (StatusCode, Value) {
    json_request(
        app,
        "POST",
        "/api/v1/auth/login",
        Some(json!({
            "email": email,
            "master_password": password
        })),
        None,
    )
    .await
}

// ─── Health endpoints ───────────────────────────────────────────────────────

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let (app, _pool) = setup().await;
    let (status, _) = json_request(app, "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn auth_health_endpoint_returns_ok() {
    let (app, _pool) = setup().await;
    let (status, _) = json_request(app, "GET", "/api/v1/auth/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
}

// ─── Registration ───────────────────────────────────────────────────────────

#[tokio::test]
async fn register_user_succeeds() {
    let (app, _pool) = setup().await;
    let (status, body) = register(app, "alice@test.com", "strongpassword").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "alice@test.com");
    assert!(body["id"].is_number(), "response should contain numeric id");
}

#[tokio::test]
async fn register_duplicate_email_returns_conflict() {
    let (app, pool) = setup().await;

    // First registration
    let (status, _) = register(app, "dup@test.com", "pass1").await;
    assert_eq!(status, StatusCode::OK);

    // Duplicate — rebuild router from same pool (oneshot consumes the router)
    let state = Arc::new(AppState { db: pool.clone() });
    let app2 = Router::new()
        .merge(api::router())
        .layer(CorsLayer::permissive())
        .layer(Extension(state));

    let (status2, _) = register(app2, "dup@test.com", "pass2").await;
    assert_eq!(status2, StatusCode::CONFLICT);
}

#[tokio::test]
async fn register_with_username_and_vault() {
    let (app, _pool) = setup().await;

    let (status, body) = json_request(
        app,
        "POST",
        "/api/v1/auth/register",
        Some(json!({
            "username": "bob",
            "email": "bob@test.com",
            "master_password": "password123",
            "encrypted_vault": "initial_encrypted_data"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "bob@test.com");
}

// ─── Login / Session ────────────────────────────────────────────────────────

#[tokio::test]
async fn login_with_correct_password_returns_token() {
    let (app, pool) = setup().await;

    // Register
    register(app, "login@test.com", "mypassword").await;

    // Login
    let state = Arc::new(AppState { db: pool.clone() });
    let app2 = Router::new()
        .merge(api::router())
        .layer(CorsLayer::permissive())
        .layer(Extension(state));

    let (status, body) = login(app2, "login@test.com", "mypassword").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["session_token"].is_string(),
        "should return a session_token"
    );
    assert!(
        body["expires_at"].is_string(),
        "should return an expires_at"
    );
}

#[tokio::test]
async fn login_with_wrong_password_returns_unauthorized() {
    let (app, pool) = setup().await;

    register(app, "wrongpw@test.com", "correctpass").await;

    let state = Arc::new(AppState { db: pool.clone() });
    let app2 = Router::new()
        .merge(api::router())
        .layer(CorsLayer::permissive())
        .layer(Extension(state));

    let (status, _) = login(app2, "wrongpw@test.com", "wrongpass").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_nonexistent_user_returns_not_found() {
    let (app, _pool) = setup().await;
    let (status, _) = login(app, "ghost@test.com", "anything").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ─── Vault CRUD ─────────────────────────────────────────────────────────────

/// Helper: register + login, return (fresh router, token).
async fn register_and_login(pool: &PgPool, email: &str, password: &str) -> (Router, String) {
    let make_app = || {
        let state = Arc::new(AppState { db: pool.clone() });
        Router::new()
            .merge(api::router())
            .route("/health", get(|| async { "zcloudpass: ok" }))
            .layer(CorsLayer::permissive())
            .layer(Extension(state))
    };

    // Register
    let (st, _) = register(make_app(), email, password).await;
    assert_eq!(st, StatusCode::OK);

    // Login
    let (st, body) = login(make_app(), email, password).await;
    assert_eq!(st, StatusCode::OK);
    let token = body["session_token"].as_str().unwrap().to_string();

    (make_app(), token)
}

#[tokio::test]
async fn get_vault_initially_returns_null() {
    let (app, pool) = setup().await;
    drop(app);
    let (app, token) = register_and_login(&pool, "vault@test.com", "pw123").await;

    let (status, body) = json_request(app, "GET", "/api/v1/vault/", None, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["encrypted_vault"].is_null(),
        "vault should be null initially"
    );
}

#[tokio::test]
async fn put_then_get_vault_round_trip() {
    let (app, pool) = setup().await;
    drop(app);
    let (app, token) = register_and_login(&pool, "roundtrip@test.com", "pw").await;

    // PUT vault
    let make_app = || {
        let state = Arc::new(AppState { db: pool.clone() });
        Router::new()
            .merge(api::router())
            .layer(CorsLayer::permissive())
            .layer(Extension(state))
    };

    let (status, _) = json_request(
        app,
        "PUT",
        "/api/v1/vault/",
        Some(json!({ "encrypted_vault": "ENCRYPTED_BLOB_ABC" })),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // GET vault
    let (status, body) =
        json_request(make_app(), "GET", "/api/v1/vault/", None, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["encrypted_vault"], "ENCRYPTED_BLOB_ABC");

    // UPDATE vault
    let (status, _) = json_request(
        make_app(),
        "PUT",
        "/api/v1/vault/",
        Some(json!({ "encrypted_vault": "UPDATED_BLOB_XYZ" })),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify update
    let (status, body) =
        json_request(make_app(), "GET", "/api/v1/vault/", None, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["encrypted_vault"], "UPDATED_BLOB_XYZ");
}

#[tokio::test]
async fn vault_without_auth_returns_unauthorized() {
    let (app, _pool) = setup().await;

    let (status, _) = json_request(app, "GET", "/api/v1/vault/", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn vault_with_invalid_token_returns_unauthorized() {
    let (app, _pool) = setup().await;

    let (status, _) =
        json_request(app, "GET", "/api/v1/vault/", None, Some("not-a-real-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ─── Change password ────────────────────────────────────────────────────────

#[tokio::test]
async fn change_password_then_login_with_new_password() {
    let (app, pool) = setup().await;
    drop(app);
    let (_app, token) = register_and_login(&pool, "chpw@test.com", "oldpass").await;

    let make_app = || {
        let state = Arc::new(AppState { db: pool.clone() });
        Router::new()
            .merge(api::router())
            .layer(CorsLayer::permissive())
            .layer(Extension(state))
    };

    // Change password
    let (status, _) = json_request(
        make_app(),
        "POST",
        "/api/v1/auth/change-password",
        Some(json!({
            "current_password": "oldpass",
            "new_password": "newpass"
        })),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Old password should fail
    let (status, _) = login(make_app(), "chpw@test.com", "oldpass").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // New password should succeed
    let (status, body) = login(make_app(), "chpw@test.com", "newpass").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["session_token"].is_string());
}

#[tokio::test]
async fn change_password_with_wrong_current_returns_unauthorized() {
    let (app, pool) = setup().await;
    drop(app);
    let (_app, token) = register_and_login(&pool, "badchpw@test.com", "realpass").await;

    let make_app = || {
        let state = Arc::new(AppState { db: pool.clone() });
        Router::new()
            .merge(api::router())
            .layer(CorsLayer::permissive())
            .layer(Extension(state))
    };

    let (status, _) = json_request(
        make_app(),
        "POST",
        "/api/v1/auth/change-password",
        Some(json!({
            "current_password": "wrongpass",
            "new_password": "newpass"
        })),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_password_without_auth_returns_unauthorized() {
    let (app, _pool) = setup().await;

    let (status, _) = json_request(
        app,
        "POST",
        "/api/v1/auth/change-password",
        Some(json!({
            "current_password": "x",
            "new_password": "y"
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ─── Session endpoint (alias for /login) ────────────────────────────────────

#[tokio::test]
async fn session_endpoint_also_works() {
    let (app, pool) = setup().await;
    register(app, "session@test.com", "pw").await;

    let state = Arc::new(AppState { db: pool.clone() });
    let app2 = Router::new()
        .merge(api::router())
        .layer(CorsLayer::permissive())
        .layer(Extension(state));

    let (status, body) = json_request(
        app2,
        "POST",
        "/api/v1/auth/session",
        Some(json!({
            "email": "session@test.com",
            "master_password": "pw"
        })),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["session_token"].is_string());
}
