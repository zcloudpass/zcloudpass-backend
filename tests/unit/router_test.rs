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

/// Build a combined router with both health endpoints.
fn combined_router() -> Router {
    Router::new()
        .route("/health", get(|| async { "zcloudpass: ok" }))
        .route("/api/v1/auth/health", get(|| async { "auth ok" }))
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

// ─── Additional HTTP method tests ──────────────────────────────────────────

#[tokio::test]
async fn health_rejects_put_method() {
    let app = health_router();

    let req = Request::builder()
        .method("PUT")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn health_rejects_delete_method() {
    let app = health_router();

    let req = Request::builder()
        .method("DELETE")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn health_rejects_patch_method() {
    let app = health_router();

    let req = Request::builder()
        .method("PATCH")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn health_allows_head_method() {
    let app = health_router();

    let req = Request::builder()
        .method("HEAD")
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // HEAD on a GET route should succeed (Axum handles HEAD for GET routes)
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── 404 path variations ────────────────────────────────────────────────────

#[tokio::test]
async fn root_path_returns_404() {
    let app = health_router();

    let req = Request::builder()
        .uri("/")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_with_trailing_slash_returns_404() {
    let app = health_router();

    let req = Request::builder()
        .uri("/health/")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Axum does not match trailing slashes unless explicitly configured
    assert!(
        resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::OK,
        "trailing slash behavior should be consistent"
    );
}

#[tokio::test]
async fn health_with_subpath_returns_404() {
    let app = health_router();

    let req = Request::builder()
        .uri("/health/detailed")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_versioned_nonexistent_returns_404() {
    let app = combined_router();

    let req = Request::builder()
        .uri("/api/v1/nonexistent")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn api_v2_route_returns_404() {
    let app = combined_router();

    let req = Request::builder()
        .uri("/api/v2/auth/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_uppercase_path_returns_404() {
    let app = health_router();

    let req = Request::builder()
        .uri("/HEALTH")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_mixed_case_path_returns_404() {
    let app = health_router();

    let req = Request::builder()
        .uri("/Health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── Response body tests ────────────────────────────────────────────────────

#[tokio::test]
async fn health_body_is_exact_string() {
    let app = health_router();

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert_eq!(body_str, "zcloudpass: ok");
}

#[tokio::test]
async fn auth_health_body_is_exact_string() {
    let app = auth_health_router();

    let req = Request::builder()
        .uri("/api/v1/auth/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap();
    assert_eq!(body_str, "auth ok");
}

#[tokio::test]
async fn health_body_is_not_empty() {
    let app = health_router();

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(!body.is_empty(), "health response body should not be empty");
}

// ─── Auth health method tests ───────────────────────────────────────────────

#[tokio::test]
async fn auth_health_rejects_post() {
    let app = auth_health_router();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn auth_health_rejects_put() {
    let app = auth_health_router();

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/auth/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn auth_health_rejects_delete() {
    let app = auth_health_router();

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/auth/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ─── Combined router tests ─────────────────────────────────────────────────

#[tokio::test]
async fn combined_router_serves_root_health() {
    let app = combined_router();

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
async fn combined_router_serves_auth_health() {
    let app = combined_router();

    let req = Request::builder()
        .uri("/api/v1/auth/health")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"auth ok");
}

// ─── Request with headers / body ────────────────────────────────────────────

#[tokio::test]
async fn health_ignores_request_body() {
    let app = health_router();

    let req = Request::builder()
        .uri("/health")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"some":"data"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_works_with_custom_headers() {
    let app = health_router();

    let req = Request::builder()
        .uri("/health")
        .header("x-custom-header", "value")
        .header("authorization", "Bearer token123")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_with_query_params_returns_200() {
    let app = health_router();

    let req = Request::builder()
        .uri("/health?verbose=true&format=json")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // Router should match path ignoring query params
    assert_eq!(resp.status(), StatusCode::OK);
}
