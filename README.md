<div align="center">
  <img src="https://raw.githubusercontent.com/zcloudpass/zcloudpass/main/assets/rounded/logo.png" alt="ZCloudPass Logo" width="200"/>
  <h1>ZCloudPass Backend</h1>
</div>

A minimal Rust backend for a client-side encrypted vault/password manager. The server provides user registration, session creation, and storage/retrieval of an opaque `encrypted_vault` blob per user. Encryption and all vault entry edits are performed by the client; the server only authenticates and stores the encrypted data.

This repository is intended as a small, opinionated reference implementation and development scaffold rather than a production-ready service.

## Quick overview

- Language & frameworks: Rust, axum (HTTP), sqlx (Postgres), tokio.
- Purpose: authenticate clients (via session tokens) and persist an opaque `encrypted_vault` string for each user.
- Important modules:
  - `src/main.rs` — application entrypoint, state, and schema provisioning (`ensure_tables`).
  - `src/api/auth.rs` — registration and session creation endpoints.
  - `src/api/vault.rs` — protected endpoints to GET/PUT the `encrypted_vault`.
  - `src/middleware/auth.rs` — `Authorization: Bearer <token>` extractor that validates sessions.
  - `INSTALLATION.md` — detailed installation, run, and usage instructions.

## Minimal quick start

At a minimum you will:
   - Ensure a Postgres instance is available and set `DATABASE_URL`.
   - Run the server from the backend directory:
     ```bash
     cd zcloudpass-backend
     cargo run
     ```
   - Use the API under `/api/v1` to register users, create sessions, and GET/PUT the encrypted vault.

For complete setup steps, examples, curl commands, and troubleshooting, read [INSTALLATION.md](./INSTALLATION.md).

## API summary

- POST `/api/v1/auth/register` — register a user.
- POST `/api/v1/auth/session` — create a session; returns a `session_token`.
- GET `/api/v1/vault/` — returns `{ "encrypted_vault": "<string|null>" }` for the authenticated user.
- PUT `/api/v1/vault/` — accepts `{ "encrypted_vault": "<string>" }` and stores it for the authenticated user.

All vault endpoints require the `Authorization: Bearer <session_token>` header.

## Important security notes

- This project stores an opaque `encrypted_vault` string in the database. All encryption/decryption must be done client-side to maintain end-to-end confidentiality.
- The current `create_session` implementation in this repository issues session tokens by email lookup and does not perform password or SRP verification. This is intentionally minimal for development and testing — you must implement proper authentication before using this code in production.
- Do not log decrypted vault data or plaintext secrets. Enforce size limits on stored blobs and add rate limiting before production use.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
