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
    // PHC strings start with $argon2
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
    assert_ne!(h1, h2, "two hashes of the same password should differ (random salt)");
}

// ─── Verification ───────────────────────────────────────────────────────────

#[test]
fn verify_correct_password_succeeds() {
    let hash = hash_password("correct_horse_battery_staple");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"correct_horse_battery_staple", &parsed);
    assert!(result.is_ok(), "correct password should verify successfully");
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
    assert!(result.is_err(), "empty password should not verify against non-empty hash");
}

#[test]
fn hash_and_verify_empty_password() {
    let hash = hash_password("");
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(b"", &parsed);
    assert!(result.is_ok(), "empty password should verify against its own hash");
}

#[test]
fn hash_and_verify_unicode_password() {
    let password = "пароль🔑密码";
    let hash = hash_password(password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "unicode password should verify against its own hash");
}

#[test]
fn hash_and_verify_long_password() {
    let password = "a".repeat(1000);
    let hash = hash_password(&password);
    let parsed = PasswordHash::new(&hash).unwrap();
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed);
    assert!(result.is_ok(), "long password should verify against its own hash");
}
