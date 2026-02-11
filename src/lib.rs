pub mod api;
pub mod middleware;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
}
