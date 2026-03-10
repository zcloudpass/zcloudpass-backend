//! Middleware helpers used by request handlers.
//!
//! Contains authentication-related request extractors and helpers.

pub mod auth;

/// Re-export `AuthUser` so callers can import `crate::middleware::AuthUser`.
pub use auth::AuthUser;
