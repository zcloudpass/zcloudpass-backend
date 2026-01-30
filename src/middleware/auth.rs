use axum::extract::FromRequestParts;
use axum::http::{StatusCode, request::Parts};
use futures::FutureExt;
use sqlx::{PgPool, Row};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: i32,
    // pub email: String,
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl futures::Future<Output = Result<Self, <Self as FromRequestParts<S>>::Rejection>>
    + std::marker::Send {
        let headers = parts.headers.clone();

        let pool_opt = parts
            .extensions
            .get::<Arc<crate::AppState>>()
            .cloned()
            .map(|app_state| app_state.db.clone());

        async move {
            let pool = match pool_opt {
                Some(p) => p,
                None => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            };

            let auth_header = headers
                .get("authorization")
                .and_then(|hv| hv.to_str().ok())
                .ok_or(StatusCode::UNAUTHORIZED)?;

            let token = if let Some(stripped) = auth_header.strip_prefix("Bearer ") {
                stripped
            } else if let Some(stripped) = auth_header.strip_prefix("bearer ") {
                stripped
            } else {
                return Err(StatusCode::UNAUTHORIZED);
            };

            validate_session_token(&pool, token).await
        }
        .boxed()
    }
}

async fn validate_session_token(pool: &PgPool, token: &str) -> Result<AuthUser, StatusCode> {
    let result = sqlx::query(
        r#"
        SELECT s.user_id, u.email
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = $1
          AND s.expires_at > now()
          AND u.account_status = 'active'
        "#,
    )
    .bind(token)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        eprintln!("Session validation error: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    match result {
        Some(row) => {
            let user_id: i32 = row
                .try_get("user_id")
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

            /*
            let email: String = row
               .try_get("email")
               .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            */

            let _ =
                sqlx::query("UPDATE sessions SET last_activity = now() WHERE session_token = $1")
                    .bind(token)
                    .execute(pool)
                    .await;

            // Ok(AuthUser { user_id, email })
            Ok(AuthUser { user_id })
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}
