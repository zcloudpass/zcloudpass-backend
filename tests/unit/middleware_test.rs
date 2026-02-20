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

#[test]
fn extracts_jwt_like_token() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123";
    let header = format!("Bearer {}", jwt);
    let result = extract_bearer_token(&header);
    assert_eq!(result.unwrap(), jwt);
}

#[test]
fn extracts_base64_encoded_token() {
    let result = extract_bearer_token("Bearer dGVzdF90b2tlbg==");
    assert_eq!(result.unwrap(), "dGVzdF90b2tlbg==");
}

#[test]
fn extracts_token_with_dots_and_dashes() {
    let result = extract_bearer_token("Bearer my.session-token.v2");
    assert_eq!(result.unwrap(), "my.session-token.v2");
}

#[test]
fn extracts_numeric_only_token() {
    let result = extract_bearer_token("Bearer 1234567890");
    assert_eq!(result.unwrap(), "1234567890");
}

#[test]
fn extracts_hexadecimal_token() {
    let result = extract_bearer_token("Bearer 0123456789abcdef");
    assert_eq!(result.unwrap(), "0123456789abcdef");
}

#[test]
fn extracts_token_with_underscores() {
    let result = extract_bearer_token("Bearer my_session_token_v3");
    assert_eq!(result.unwrap(), "my_session_token_v3");
}

#[test]
fn extracts_very_long_token() {
    let long_token = "a".repeat(2048);
    let header = format!("Bearer {}", long_token);
    let result = extract_bearer_token(&header);
    assert_eq!(result.unwrap(), long_token);
}

#[test]
fn extracts_single_char_token() {
    let result = extract_bearer_token("Bearer x");
    assert_eq!(result.unwrap(), "x");
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

#[test]
fn rejects_camel_case_bearer() {
    let result = extract_bearer_token("bEaReR my-token");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_digest_auth_header() {
    let result = extract_bearer_token("Digest username=\"admin\"");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_negotiate_auth_header() {
    let result = extract_bearer_token("Negotiate YIIJvwYGKw...");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_only_whitespace() {
    let result = extract_bearer_token("   ");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_bearer_tab_instead_of_space() {
    let result = extract_bearer_token("Bearer\tmy-token");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_bearer_newline_instead_of_space() {
    let result = extract_bearer_token("Bearer\nmy-token");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_bearer_with_colon_instead_of_space() {
    // "Bearer:" does NOT match "Bearer " prefix (colon ≠ space)
    let result = extract_bearer_token("Bearer:my-token");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_random_string() {
    let result = extract_bearer_token("some random string");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_api_key_prefix() {
    let result = extract_bearer_token("ApiKey sk-abc123def456");
    assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
}

#[test]
fn rejects_bearer_prefix_with_double_colon() {
    let result = extract_bearer_token("Bearer::my-token");
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

#[test]
fn token_with_url_encoded_characters() {
    let result = extract_bearer_token("Bearer token%20with%20spaces");
    assert_eq!(result.unwrap(), "token%20with%20spaces");
}

#[test]
fn token_with_pipe_character() {
    let result = extract_bearer_token("Bearer token|part2");
    assert_eq!(result.unwrap(), "token|part2");
}

#[test]
fn token_with_at_symbol() {
    let result = extract_bearer_token("Bearer user@domain.com");
    assert_eq!(result.unwrap(), "user@domain.com");
}

#[test]
fn token_with_hash() {
    let result = extract_bearer_token("Bearer token#fragment");
    assert_eq!(result.unwrap(), "token#fragment");
}

#[test]
fn lowercase_bearer_with_trailing_whitespace() {
    let result = extract_bearer_token("bearer  my-token   ");
    assert_eq!(result.unwrap(), "my-token");
}

#[test]
fn bearer_token_is_a_json_string() {
    let result = extract_bearer_token("Bearer {\"token\":\"abc\"}");
    assert_eq!(result.unwrap(), "{\"token\":\"abc\"}");
}

#[test]
fn bearer_with_multiple_spaces_between_bearer_and_token() {
    // "Bearer   token" → strip "Bearer " → "  token" → trim → "token"
    let result = extract_bearer_token("Bearer   token");
    assert_eq!(result.unwrap(), "token");
}

#[test]
fn result_is_ok_variant_for_valid_bearer() {
    let result = extract_bearer_token("Bearer valid-token");
    assert!(result.is_ok());
}

#[test]
fn result_is_err_variant_for_invalid_bearer() {
    let result = extract_bearer_token("Invalid header");
    assert!(result.is_err());
}

#[test]
fn error_status_is_always_401() {
    let invalid_headers = vec![
        "",
        "Basic abc",
        "Token xyz",
        "BEARER abc",
        "Bearerabc",
        "   ",
        "random",
    ];
    for header in invalid_headers {
        let result = extract_bearer_token(header);
        assert_eq!(
            result.unwrap_err(),
            StatusCode::UNAUTHORIZED,
            "header '{}' should produce 401 UNAUTHORIZED",
            header
        );
    }
}
