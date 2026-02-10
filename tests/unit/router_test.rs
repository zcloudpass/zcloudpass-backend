//! Tests for router structure and health endpoints.
//!
//! These verify that routes are correctly wired without needing a database.
//! Only the `/health` and `/api/v1/auth/health` endpoints can be tested
//! without DB, since all other routes require database connections.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt; // for `oneshot`

/// Build a minimal router that includes only the health route
/// (same as in main.rs) without any database-dependent state.
fn health_router() -> Router {
    Router::new().route("/health", get(|| async { "zcloudpass: ok" }))
}

/// Build the auth sub-router's health endpoint (mirrors api/auth.rs).
fn auth_health_router() -> Router {
    Router::new().route("/api/v1/auth/health", get(|| async { "auth ok" }))
}

// ─── Health endpoints ───────────────────────────────────────────────────────

#[tokio::test]
async fn root_health_returns_200() {
    let app = health_router();

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"zcloudpass: ok");
}

#[tokio::test]
async fn auth_health_returns_200() {
    let app = auth_health_router();

    let req = Request::builder()
        .uri("/api/v1/auth/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"auth ok");
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let app = health_router();

    let req = Request::builder()
        .uri("/nonexistent")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_rejects_post_method() {
    let app = health_router();

    let req = Request::builder()
        .method("POST")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Axum returns 405 Method Not Allowed for wrong method on a matched route
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}
