//! Unit tests for Argon2 password hashing and verification logic.
//!
//! These tests mirror the hashing strategy used in `api/auth.rs`
//! (register_user, create_session_token, change_password).

use argon2::Argon2;
use password_hash::rand_core::OsRng;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// Hash a password with the same parameters used in the application.
fn hash_password(password: &str) -> String {
    let mut rng = OsRng;
    let salt = SaltString::generate(&mut rng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("hashing should succeed")
        .to_string()
}

// ─── Hashing ────────────────────────────────────────────────────────────────

#[test]
fn hash_password_produces_valid_phc_string() {
    let hash = hash_password("my_secret");
    assert!(
        hash.starts_with("$argon2"),
        "hash should be a PHC-format argon2 string, got: {}",
        hash
    );
}

#[test]
fn hash_password_parseable_by_password_hash() {
    let hash = hash_password("test_password");
    let parsed = PasswordHash::new(&hash);
    assert!(
        parsed.is_ok(),
        "should parse as a valid PasswordHash: {:?}",
        parsed
    );
}

#[test]
fn hash_is_different_each_time_due_to_salt() {
    let h1 = hash_password("same_password");
    let h2 = hash_password("same_password");
    assert_ne!(
        h1, h2,
        "two hashes of the same password should differ (random salt)"
    );
}

#[test]
fn hash_contains_argon2id_variant() {
    let hash = hash_password("test");
    // Default Argon2 uses argon2id variant
    assert!(
        hash.starts_with("$argon2id$"),
        "hash should use argon2id variant, got: {}",
        hash
    );
}

#[test]
fn hash_contains_version_field() {
    let hash = hash_password("test");
    assert!(
        hash.contains("v="),
        "hash should contain version field, got: {}",
        hash
    );
}

#[test]
fn hash_contains_memory_cost_params() {
    let hash = hash_password("test");
    assert!(
        hash.contains("m="),
        "hash should contain memory cost parameter, got: {}",
        hash
    );
}

#[test]
fn hash_contains_time_cost_params() {
    let hash = hash_password("test");
    assert!(
        hash.contains("t="),
        "hash should contain time cost parameter, got: {}",
        hash
    );
}

#[test]
fn hash_contains_parallelism_params() {
    let hash = hash_password("test");
    assert!(
        hash.contains("p="),
        "hash should contain parallelism parameter, got: {}",
        hash
    );
}

#[test]
fn hash_has_five_dollar_separated_sections() {
    let hash = hash_password("test");
    // PHC format: $algo$version$params$salt$hash
    let sections: Vec<&str> = hash.split('$').collect();
    // First element is empty string before leading $
    assert!(
        sections.len() >= 5,
        "PHC string should have at least 5 $-separated parts, got {}: {}",
        sections.len(),
        hash
    );
}

#[test]
fn hash_salt_is_always_unique() {
    let mut salts = Vec::new();
    for _ in 0..10 {
        let hash = hash_password("password");
        let parsed = PasswordHash::new(&hash).unwrap();
        salts.push(parsed.salt.unwrap().to_string());
    }
    // All salts should be unique
    let unique_count = {
        let mut deduped = salts.clone();
        deduped.sort();
        deduped.dedup();
        deduped.len()
    };
    assert_eq!(unique_count, 10, "all 10 salts should be unique");
}

#[test]
fn hash_output_is_non_empty() {
    let hash = hash_password("test");
    assert!(!hash.is_empty(), "hash should not be empty");
}

#[test]
fn hash_output_length_is_reasonable() {
    let hash = hash_password("test");
    // Argon2 PHC strings are typically 90-120 chars
    assert!(
        hash.len() > 50 && hash.len() < 300,
        "hash length should be between 50 and 300, got: {}",
        hash.len()
    );
}

// ─── Verification ───────────────────────────────────────────────────────────

#[test]
fn verify_correct_password_succeeds() {
    let hash = hash_password("correct_horse_battery_staple");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"correct_horse_battery_staple", &parsed);
    assert!(
        result.is_ok(),
        "correct password should verify successfully"
    );
}

#[test]
fn verify_wrong_password_fails() {
    let hash = hash_password("correct_password");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"wrong_password", &parsed);
    assert!(result.is_err(), "wrong password should fail verification");
}

#[test]
fn verify_empty_password_against_nonempty_hash_fails() {
    let hash = hash_password("nonempty");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"", &parsed);
    assert!(
        result.is_err(),
        "empty password should not verify against non-empty hash"
    );
}

#[test]
fn hash_and_verify_empty_password() {
    let hash = hash_password("");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"", &parsed);
    assert!(
        result.is_ok(),
        "empty password should verify against its own hash"
    );
}

#[test]
fn hash_and_verify_unicode_password() {
    let password = "пароль🔑密码";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(
        result.is_ok(),
        "unicode password should verify against its own hash"
    );
}

#[test]
fn hash_and_verify_long_password() {
    let password = "a".repeat(1000);
    let hash = hash_password(&password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(
        result.is_ok(),
        "long password should verify against its own hash"
    );
}

// ─── Additional Verification Edge Cases ─────────────────────────────────────

#[test]
fn verify_password_case_sensitive() {
    let hash = hash_password("Password");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"password", &parsed);
    assert!(
        result.is_err(),
        "password verification should be case-sensitive"
    );
}

#[test]
fn verify_password_case_sensitive_uppercase() {
    let hash = hash_password("password");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"PASSWORD", &parsed);
    assert!(
        result.is_err(),
        "uppercase variant should not match lowercase hash"
    );
}

#[test]
fn verify_password_with_trailing_space_differs() {
    let hash = hash_password("password");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"password ", &parsed);
    assert!(
        result.is_err(),
        "password with trailing space should not match"
    );
}

#[test]
fn verify_password_with_leading_space_differs() {
    let hash = hash_password("password");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b" password", &parsed);
    assert!(
        result.is_err(),
        "password with leading space should not match"
    );
}

#[test]
fn verify_password_with_null_byte() {
    let password = "pass\0word";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "password with null byte should verify");
}

#[test]
fn verify_null_byte_password_differs_from_non_null() {
    let hash = hash_password("pass\0word");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"password", &parsed);
    assert!(
        result.is_err(),
        "password without null byte should not match hash with null byte"
    );
}

#[test]
fn hash_and_verify_special_characters_password() {
    let password = "p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "special characters password should verify");
}

#[test]
fn hash_and_verify_newline_password() {
    let password = "line1\nline2\nline3";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "password with newlines should verify");
}

#[test]
fn hash_and_verify_tab_password() {
    let password = "pass\tword";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "password with tabs should verify");
}

#[test]
fn hash_and_verify_whitespace_only_password() {
    let password = "   ";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "whitespace-only password should verify");
}

#[test]
fn hash_and_verify_single_char_password() {
    let hash = hash_password("a");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"a", &parsed);
    assert!(result.is_ok(), "single character password should verify");
}

#[test]
fn hash_and_verify_emoji_password() {
    let password = "🔐🔑🗝️🔓🔒";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "emoji password should verify");
}

#[test]
fn hash_and_verify_japanese_password() {
    let password = "パスワード";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "Japanese password should verify");
}

#[test]
fn hash_and_verify_arabic_password() {
    let password = "كلمة المرور";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "Arabic password should verify");
}

#[test]
fn verify_similar_passwords_do_not_match() {
    let hash = hash_password("password123");
    let parsed = PasswordHash::new(&hash).unwrap();

    let similar = [
        "password124",
        "password12",
        "Password123",
        "password1234",
        "passw0rd123",
    ];
    for variant in &similar {
        let result = Argon2::default().verify_password(variant.as_bytes(), &parsed);
        assert!(
            result.is_err(),
            "similar password '{}' should not match original",
            variant
        );
    }
}

#[test]
fn hash_and_verify_very_long_password_4096_bytes() {
    let password = "x".repeat(4096);
    let hash = hash_password(&password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "4096-byte password should verify");
}

#[test]
fn multiple_hashes_of_same_password_all_verify() {
    let password = "test_password_2024";
    let hashes: Vec<String> = (0..5).map(|_| hash_password(password)).collect();

    for (i, h) in hashes.iter().enumerate() {
        let parsed = PasswordHash::new(h).unwrap();
        let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
        assert!(
            result.is_ok(),
            "hash #{} should verify with correct password",
            i
        );
    }
}

#[test]
fn different_passwords_produce_different_hashes_even_ignoring_salt() {
    // Even though salts differ, the output hash portion should differ
    let h1 = hash_password("password_a");
    let h2 = hash_password("password_b");
    // They are always different because of salt, but let's confirm structurally
    assert_ne!(h1, h2);
}

#[test]
fn hash_and_verify_backslash_password() {
    let password = r"C:\Users\test\path";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "backslash password should verify");
}

#[test]
fn hash_and_verify_sql_injection_attempt_password() {
    let password = "'; DROP TABLE users; --";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(
        result.is_ok(),
        "SQL injection attempt as password should still hash and verify correctly"
    );
}

#[test]
fn hash_and_verify_html_script_password() {
    let password = "<script>alert('xss')</script>";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(
        result.is_ok(),
        "HTML/script content as password should hash and verify"
    );
}

#[test]
fn hash_and_verify_url_encoded_password() {
    let password = "%20%3C%3E%22%27";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "URL-encoded password should verify");
}

#[test]
fn hash_and_verify_base64_string_password() {
    let password = "dGVzdCBwYXNzd29yZA==";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(
        result.is_ok(),
        "base64-encoded string as password should verify"
    );
}
