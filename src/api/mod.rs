use axum::Router;

pub mod auth;
pub mod vault;

pub fn router() -> Router {
    Router::new()
        .nest("/api/v1/auth", auth::router())
        // Register vault router for both forms to handle trailing slash requests
        .nest("/api/v1/vault", vault::router())
        .nest("/api/v1/vault/", vault::router())
}
