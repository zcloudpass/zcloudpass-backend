//! Unit tests for the auth middleware's bearer‑token extraction logic.

use axum::http::StatusCode;
use zcloudpass_backend::middleware::auth::extract_bearer_token;

// ─── Successful extraction ──────────────────────────────────────────────────

#[test]
fn extracts_token_with_uppercase_bearer() {
    let result = extract_bearer_token("Bearer my-session-token-123");
    assert_eq!(result.unwrap(), "my-session-token-123");
}

#[test]
fn extracts_token_with_lowercase_bearer() {
    let result = extract_bearer_token("bearer my-session-token-456");
    assert_eq!(result.unwrap(), "my-session-token-456");
}

#[test]
fn trims_whitespace_around_token() {
    let result = extract_bearer_token("Bearer   tok-with-spaces   ");
    assert_eq!(result.unwrap(), "tok-with-spaces");
}

#[test]
fn extracts_uuid_token() {
    let result = extract_bearer_token("Bearer 550e8400-e29b-41d4-a716-446655440000");
    assert_eq!(result.unwrap(), "550e8400-e29b-41d4-a716-446655440000");
}

// ─── Rejection cases ────────────────────────────────────────────────────────

#[test]
fn rejects_missing_bearer_prefix() {
    let result = extract_bearer_token("Token abc123");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_basic_auth_header() {
    let result = extract_bearer_token("Basic dXNlcjpwYXNz");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_empty_string() {
    let result = extract_bearer_token("");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_bearer_without_space() {
    // "Bearerabc" is not "Bearer abc"
    let result = extract_bearer_token("Bearerabc");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_mixed_case_bearer() {
    // Only "Bearer " and "bearer " are accepted
    let result = extract_bearer_token("BEARER my-token");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

// ─── Edge cases ─────────────────────────────────────────────────────────────

#[test]
fn bearer_prefix_only_returns_empty_trimmed_string() {
    // "Bearer " with nothing after it yields an empty string after trim
    let result = extract_bearer_token("Bearer ");
    assert_eq!(result.unwrap(), "");
}

#[test]
fn token_with_special_characters() {
    let result = extract_bearer_token("Bearer abc+def/ghi=jkl");
    assert_eq!(result.unwrap(), "abc+def/ghi=jkl");
}
