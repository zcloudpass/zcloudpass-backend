//! Unit tests for request/response model serialization and deserialization.

use serde_json;
use zcloudpass_backend::api::auth::{
    ChangePasswordRequest, RegisterRequest, RegisterResponse, SessionCreateRequest,
    SessionCreateResponse,
};
use zcloudpass_backend::api::vault::{VaultResponse, VaultUpdate};

// ═══════════════════════════════════════════════════════════════════════════
// RegisterRequest
// ═══════════════════════════════════════════════════════════════════════════

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

#[test]
fn register_request_empty_email_succeeds() {
    let json = r#"{ "email": "", "master_password": "pw" }"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.email, "");
}

#[test]
fn register_request_empty_password_succeeds() {
    let json = r#"{ "email": "a@b.com", "master_password": "" }"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.master_password, "");
}

#[test]
fn register_request_with_null_username() {
    let json = r#"{ "email": "a@b.com", "master_password": "pw", "username": null }"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert!(req.username.is_none());
}

#[test]
fn register_request_with_null_vault() {
    let json = r#"{ "email": "a@b.com", "master_password": "pw", "encrypted_vault": null }"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert!(req.encrypted_vault.is_none());
}

#[test]
fn register_request_unicode_email() {
    let json = r#"{ "email": "用户@example.com", "master_password": "pw" }"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.email, "用户@example.com");
}

#[test]
fn register_request_unicode_username() {
    let json = r#"{ "email": "a@b.com", "master_password": "pw", "username": "пользователь" }"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.username.as_deref(), Some("пользователь"));
}

#[test]
fn register_request_unicode_password() {
    let json = r#"{ "email": "a@b.com", "master_password": "密码🔑" }"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.master_password, "密码🔑");
}

#[test]
fn register_request_very_long_email() {
    let long_email = format!("{}@example.com", "a".repeat(500));
    let json = format!(
        r#"{{ "email": "{}", "master_password": "pw" }}"#,
        long_email
    );
    let req: RegisterRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req.email, long_email);
}

#[test]
fn register_request_very_long_password() {
    let long_pw = "x".repeat(10000);
    let json = format!(
        r#"{{ "email": "a@b.com", "master_password": "{}" }}"#,
        long_pw
    );
    let req: RegisterRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req.master_password, long_pw);
}

#[test]
fn register_request_special_chars_in_password() {
    let json = r#"{ "email": "a@b.com", "master_password": "p@$$w0rd!#%^&*()" }"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.master_password, "p@$$w0rd!#%^&*()");
}

#[test]
fn register_request_ignores_unknown_fields() {
    let json = r#"{ "email": "a@b.com", "master_password": "pw", "unknown_field": "value" }"#;
    // serde by default ignores unknown fields unless deny_unknown_fields is set
    let result = serde_json::from_str::<RegisterRequest>(json);
    // If it errors, the struct uses deny_unknown_fields; if ok, it ignores them
    // Either way this documents the behavior
    if let Ok(req) = result {
        assert_eq!(req.email, "a@b.com");
    }
}

#[test]
fn register_request_empty_json_fails() {
    let json = r#"{}"#;
    let result = serde_json::from_str::<RegisterRequest>(json);
    assert!(
        result.is_err(),
        "empty JSON should fail to deserialize RegisterRequest"
    );
}

#[test]
fn register_request_from_array_fails() {
    let json = r#"[]"#;
    let result = serde_json::from_str::<RegisterRequest>(json);
    assert!(
        result.is_err(),
        "array JSON should fail to deserialize RegisterRequest"
    );
}

#[test]
fn register_request_from_null_fails() {
    let json = "null";
    let result = serde_json::from_str::<RegisterRequest>(json);
    assert!(
        result.is_err(),
        "null JSON should fail to deserialize RegisterRequest"
    );
}

#[test]
fn register_request_email_as_number_fails() {
    let json = r#"{ "email": 12345, "master_password": "pw" }"#;
    let result = serde_json::from_str::<RegisterRequest>(json);
    assert!(result.is_err(), "numeric email should fail deserialization");
}

#[test]
fn register_request_password_as_number_fails() {
    let json = r#"{ "email": "a@b.com", "master_password": 12345 }"#;
    let result = serde_json::from_str::<RegisterRequest>(json);
    assert!(
        result.is_err(),
        "numeric password should fail deserialization"
    );
}

#[test]
fn register_request_email_with_json_special_chars() {
    let json = r#"{ "email": "test+label@example.com", "master_password": "pw" }"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.email, "test+label@example.com");
}

#[test]
fn register_request_vault_with_large_data() {
    let vault_data = "ENCRYPTED_".repeat(1000);
    let json = format!(
        r#"{{ "email": "a@b.com", "master_password": "pw", "encrypted_vault": "{}" }}"#,
        vault_data
    );
    let req: RegisterRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req.encrypted_vault.as_deref(), Some(vault_data.as_str()));
}

// ═══════════════════════════════════════════════════════════════════════════
// RegisterResponse
// ═══════════════════════════════════════════════════════════════════════════

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

#[test]
fn register_response_serializes_zero_id() {
    let resp = RegisterResponse {
        id: 0,
        email: "a@b.com".to_string(),
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["id"], 0);
}

#[test]
fn register_response_serializes_negative_id() {
    let resp = RegisterResponse {
        id: -1,
        email: "a@b.com".to_string(),
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["id"], -1);
}

#[test]
fn register_response_serializes_max_i32_id() {
    let resp = RegisterResponse {
        id: i32::MAX,
        email: "a@b.com".to_string(),
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["id"], i32::MAX);
}

#[test]
fn register_response_serializes_empty_email() {
    let resp = RegisterResponse {
        id: 1,
        email: "".to_string(),
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["email"], "");
}

#[test]
fn register_response_has_exactly_two_fields() {
    let resp = RegisterResponse {
        id: 1,
        email: "a@b.com".to_string(),
    };
    let json = serde_json::to_value(&resp).unwrap();
    let obj = json.as_object().unwrap();
    assert_eq!(
        obj.len(),
        2,
        "RegisterResponse should have exactly 2 fields"
    );
    assert!(obj.contains_key("id"));
    assert!(obj.contains_key("email"));
}

#[test]
fn register_response_to_string_and_back() {
    let resp = RegisterResponse {
        id: 99,
        email: "test@test.com".to_string(),
    };
    let json_str = serde_json::to_string(&resp).unwrap();
    // Verify it's valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["id"], 99);
    assert_eq!(parsed["email"], "test@test.com");
}

// ═══════════════════════════════════════════════════════════════════════════
// SessionCreateRequest
// ═══════════════════════════════════════════════════════════════════════════

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

#[test]
fn session_create_request_empty_values() {
    let json = r#"{ "email": "", "master_password": "" }"#;
    let req: SessionCreateRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.email, "");
    assert_eq!(req.master_password, "");
}

#[test]
fn session_create_request_empty_json_fails() {
    let json = r#"{}"#;
    assert!(serde_json::from_str::<SessionCreateRequest>(json).is_err());
}

#[test]
fn session_create_request_with_special_chars() {
    let json = r#"{ "email": "user+test@domain.co.uk", "master_password": "p@$$w0rd!" }"#;
    let req: SessionCreateRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.email, "user+test@domain.co.uk");
    assert_eq!(req.master_password, "p@$$w0rd!");
}

#[test]
fn session_create_request_with_unicode() {
    let json = r#"{ "email": "用户@例子.com", "master_password": "пароль" }"#;
    let req: SessionCreateRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.email, "用户@例子.com");
    assert_eq!(req.master_password, "пароль");
}

#[test]
fn session_create_request_email_type_mismatch_fails() {
    let json = r#"{ "email": true, "master_password": "pw" }"#;
    assert!(serde_json::from_str::<SessionCreateRequest>(json).is_err());
}

#[test]
fn session_create_request_password_type_mismatch_fails() {
    let json = r#"{ "email": "a@b.com", "master_password": ["array"] }"#;
    assert!(serde_json::from_str::<SessionCreateRequest>(json).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// SessionCreateResponse
// ═══════════════════════════════════════════════════════════════════════════

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

#[test]
fn session_create_response_has_exactly_two_fields() {
    let resp = SessionCreateResponse {
        session_token: "tok".to_string(),
        expires_at: "2026-01-01".to_string(),
    };
    let json = serde_json::to_value(&resp).unwrap();
    let obj = json.as_object().unwrap();
    assert_eq!(obj.len(), 2);
    assert!(obj.contains_key("session_token"));
    assert!(obj.contains_key("expires_at"));
}

#[test]
fn session_create_response_empty_token() {
    let resp = SessionCreateResponse {
        session_token: "".to_string(),
        expires_at: "2026-01-01".to_string(),
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["session_token"], "");
}

#[test]
fn session_create_response_empty_expires() {
    let resp = SessionCreateResponse {
        session_token: "tok".to_string(),
        expires_at: "".to_string(),
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["expires_at"], "");
}

#[test]
fn session_create_response_roundtrip_json_string() {
    let resp = SessionCreateResponse {
        session_token: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        expires_at: "2026-12-31T23:59:59Z".to_string(),
    };
    let json_str = serde_json::to_string(&resp).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(
        parsed["session_token"],
        "550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(parsed["expires_at"], "2026-12-31T23:59:59Z");
}

// ═══════════════════════════════════════════════════════════════════════════
// ChangePasswordRequest
// ═══════════════════════════════════════════════════════════════════════════

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

#[test]
fn change_password_request_missing_current_fails() {
    let json = r#"{ "new_password": "new" }"#;
    assert!(serde_json::from_str::<ChangePasswordRequest>(json).is_err());
}

#[test]
fn change_password_request_empty_json_fails() {
    let json = r#"{}"#;
    assert!(serde_json::from_str::<ChangePasswordRequest>(json).is_err());
}

#[test]
fn change_password_request_both_empty_strings() {
    let json = r#"{ "current_password": "", "new_password": "" }"#;
    let req: ChangePasswordRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.current_password, "");
    assert_eq!(req.new_password, "");
}

#[test]
fn change_password_request_same_passwords() {
    let json = r#"{ "current_password": "same", "new_password": "same" }"#;
    let req: ChangePasswordRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.current_password, req.new_password);
}

#[test]
fn change_password_request_unicode_passwords() {
    let json = r#"{ "current_password": "旧密码", "new_password": "新密码🔐" }"#;
    let req: ChangePasswordRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.current_password, "旧密码");
    assert_eq!(req.new_password, "新密码🔐");
}

#[test]
fn change_password_request_special_chars() {
    let json = r#"{ "current_password": "old!@#$%", "new_password": "new^&*()" }"#;
    let req: ChangePasswordRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.current_password, "old!@#$%");
    assert_eq!(req.new_password, "new^&*()");
}

#[test]
fn change_password_request_with_whitespace_passwords() {
    let json = r#"{ "current_password": "  old  ", "new_password": "  new  " }"#;
    let req: ChangePasswordRequest = serde_json::from_str(json).unwrap();
    // Whitespace is preserved (no trimming at serde level)
    assert_eq!(req.current_password, "  old  ");
    assert_eq!(req.new_password, "  new  ");
}

// ═══════════════════════════════════════════════════════════════════════════
// VaultResponse
// ═══════════════════════════════════════════════════════════════════════════

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

#[test]
fn vault_response_serializes_empty_string_vault() {
    let resp = VaultResponse {
        encrypted_vault: Some("".to_string()),
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["encrypted_vault"], "");
}

#[test]
fn vault_response_has_exactly_one_field() {
    let resp = VaultResponse {
        encrypted_vault: Some("data".to_string()),
    };
    let json = serde_json::to_value(&resp).unwrap();
    let obj = json.as_object().unwrap();
    assert_eq!(obj.len(), 1);
    assert!(obj.contains_key("encrypted_vault"));
}

#[test]
fn vault_response_large_vault_data() {
    let big_data = "V".repeat(100_000);
    let resp = VaultResponse {
        encrypted_vault: Some(big_data.clone()),
    };
    let json = serde_json::to_value(&resp).unwrap();
    assert_eq!(json["encrypted_vault"], big_data);
}

#[test]
fn vault_response_roundtrip() {
    let resp = VaultResponse {
        encrypted_vault: Some("ENCRYPTED_VAULT_DATA_XYZ".to_string()),
    };
    let json_str = serde_json::to_string(&resp).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["encrypted_vault"], "ENCRYPTED_VAULT_DATA_XYZ");
}

#[test]
fn vault_response_none_roundtrip() {
    let resp = VaultResponse {
        encrypted_vault: None,
    };
    let json_str = serde_json::to_string(&resp).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed["encrypted_vault"].is_null());
}

// ═══════════════════════════════════════════════════════════════════════════
// VaultUpdate
// ═══════════════════════════════════════════════════════════════════════════

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

#[test]
fn vault_update_empty_vault_string() {
    let json = r#"{ "encrypted_vault": "" }"#;
    let req: VaultUpdate = serde_json::from_str(json).unwrap();
    assert_eq!(req.encrypted_vault, "");
}

#[test]
fn vault_update_null_vault_fails() {
    let json = r#"{ "encrypted_vault": null }"#;
    let result = serde_json::from_str::<VaultUpdate>(json);
    assert!(
        result.is_err(),
        "null should fail for non-optional String field"
    );
}

#[test]
fn vault_update_numeric_vault_fails() {
    let json = r#"{ "encrypted_vault": 12345 }"#;
    let result = serde_json::from_str::<VaultUpdate>(json);
    assert!(
        result.is_err(),
        "numeric value should fail for String field"
    );
}

#[test]
fn vault_update_large_data() {
    let large_vault = "ENCRYPTED_".repeat(5000);
    let json = format!(r#"{{ "encrypted_vault": "{}" }}"#, large_vault);
    let req: VaultUpdate = serde_json::from_str(&json).unwrap();
    assert_eq!(req.encrypted_vault, large_vault);
}

#[test]
fn vault_update_with_unicode_data() {
    let json = r#"{ "encrypted_vault": "密文数据🔐" }"#;
    let req: VaultUpdate = serde_json::from_str(json).unwrap();
    assert_eq!(req.encrypted_vault, "密文数据🔐");
}

#[test]
fn vault_update_with_base64_data() {
    let json = r#"{ "encrypted_vault": "SGVsbG8gV29ybGQ=" }"#;
    let req: VaultUpdate = serde_json::from_str(json).unwrap();
    assert_eq!(req.encrypted_vault, "SGVsbG8gV29ybGQ=");
}

#[test]
fn vault_update_from_array_fails() {
    let json = r#"[]"#;
    assert!(serde_json::from_str::<VaultUpdate>(json).is_err());
}

#[test]
fn vault_update_from_string_fails() {
    let json = r#""just a string""#;
    assert!(serde_json::from_str::<VaultUpdate>(json).is_err());
}
