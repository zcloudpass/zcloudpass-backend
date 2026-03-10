//! API router composition for the backend.
//!
//! This module wires the auth and vault routers into the top-level
//! `/api/v1/...` namespace used by the HTTP server.

use axum::Router;

pub mod auth;
pub mod vault;

/// Compose and return the top-level API `Router`.
pub fn router() -> Router {
    Router::new()
        .nest("/api/v1/auth", auth::router())
        .nest("/api/v1/vault", vault::router())
}
