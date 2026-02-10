//! Unit tests for request/response model serialization and deserialization.

use serde_json;
use zcloudpass_backend::api::auth::{
    ChangePasswordRequest, RegisterRequest, RegisterResponse, SessionCreateRequest,
    SessionCreateResponse,
};
use zcloudpass_backend::api::vault::{VaultResponse, VaultUpdate};

// ─── RegisterRequest ────────────────────────────────────────────────────────

#[test]
fn register_request_deserializes_all_fields() {
    let json = r#"{
        "username": "alice",
        "email": "alice@example.com",
        "master_password": "s3cret!",
        "encrypted_vault": "ENCRYPTED_DATA"
    }"#;

    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.username.as_deref(), Some("alice"));
    assert_eq!(req.email, "alice@example.com");
    assert_eq!(req.master_password, "s3cret!");
    assert_eq!(req.encrypted_vault.as_deref(), Some("ENCRYPTED_DATA"));
}

#[test]
fn register_request_optional_fields_absent() {
    let json = r#"{
        "email": "bob@example.com",
        "master_password": "password123"
    }"#;

    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert!(req.username.is_none());
    assert_eq!(req.email, "bob@example.com");
    assert_eq!(req.master_password, "password123");
    assert!(req.encrypted_vault.is_none());
}

#[test]
fn register_request_missing_required_email_fails() {
    let json = r#"{ "master_password": "s3cret!" }"#;
    let result = serde_json::from_str::<RegisterRequest>(json);
    assert!(result.is_err());
}

#[test]
fn register_request_missing_required_password_fails() {
    let json = r#"{ "email": "a@b.com" }"#;
    let result = serde_json::from_str::<RegisterRequest>(json);
    assert!(result.is_err());
}

// ─── RegisterResponse ───────────────────────────────────────────────────────

#[test]
fn register_response_serializes_correctly() {
    let resp = RegisterResponse {
        id: 42,
        email: "alice@example.com".to_string(),
    };

    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["id"], 42);
    assert_eq!(json["email"], "alice@example.com");
}

// ─── SessionCreateRequest ───────────────────────────────────────────────────

#[test]
fn session_create_request_deserializes() {
    let json = r#"{
        "email": "alice@example.com",
        "master_password": "s3cret!"
    }"#;

    let req: SessionCreateRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.email, "alice@example.com");
    assert_eq!(req.master_password, "s3cret!");
}

#[test]
fn session_create_request_missing_fields_fails() {
    let json = r#"{ "email": "a@b.com" }"#;
    assert!(serde_json::from_str::<SessionCreateRequest>(json).is_err());

    let json = r#"{ "master_password": "pw" }"#;
    assert!(serde_json::from_str::<SessionCreateRequest>(json).is_err());
}

// ─── SessionCreateResponse ──────────────────────────────────────────────────

#[test]
fn session_create_response_serializes() {
    let resp = SessionCreateResponse {
        session_token: "tok-abc-123".to_string(),
        expires_at: "2026-01-01T00:00:00Z".to_string(),
    };

    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["session_token"], "tok-abc-123");
    assert_eq!(json["expires_at"], "2026-01-01T00:00:00Z");
}

// ─── ChangePasswordRequest ──────────────────────────────────────────────────

#[test]
fn change_password_request_deserializes() {
    let json = r#"{
        "current_password": "old_pass",
        "new_password": "new_pass"
    }"#;

    let req: ChangePasswordRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.current_password, "old_pass");
    assert_eq!(req.new_password, "new_pass");
}

#[test]
fn change_password_request_missing_fields_fails() {
    let json = r#"{ "current_password": "old" }"#;
    assert!(serde_json::from_str::<ChangePasswordRequest>(json).is_err());
}

// ─── VaultResponse ──────────────────────────────────────────────────────────

#[test]
fn vault_response_serializes_with_data() {
    let resp = VaultResponse {
        encrypted_vault: Some("ENCRYPTED".to_string()),
    };

    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["encrypted_vault"], "ENCRYPTED");
}

#[test]
fn vault_response_serializes_with_none() {
    let resp = VaultResponse {
        encrypted_vault: None,
    };

    let json = serde_json::to_value(&resp).unwrap();
    assert!(json["encrypted_vault"].is_null());
}

// ─── VaultUpdate ────────────────────────────────────────────────────────────

#[test]
fn vault_update_deserializes() {
    let json = r#"{ "encrypted_vault": "NEW_ENCRYPTED_DATA" }"#;
    let req: VaultUpdate = serde_json::from_str(json).unwrap();
    assert_eq!(req.encrypted_vault, "NEW_ENCRYPTED_DATA");
}

#[test]
fn vault_update_missing_field_fails() {
    let json = r#"{}"#;
    assert!(serde_json::from_str::<VaultUpdate>(json).is_err());
}
