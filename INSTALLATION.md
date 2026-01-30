# Installation and Usage Guide for zcloudpass-backend

This document provides a comprehensive, step-by-step installation and usage guide for the zcloudpass-backend Rust service. It covers prerequisites, local database setup (Postgres), environment configuration, building and running the server, database reset options, example API requests for common flows (register, create session, get/update vault), troubleshooting tips, and recommended next steps for production hardening.

## Table of contents
1. Prerequisites
2. Environment variables
3. Database setup
   - Local Postgres
   - Dockerized Postgres
4. Build and run (local)
5. Resetting or clearing the database
   - Full drop & recreate
   - Truncate (keep schema)
   - Drop tables (let the server recreate)
   - Backup before destructive actions
6. API usage examples (curl)
   - Register user
   - Create session (get token)
   - Get vault
   - Update vault
7. Postman and testing tips
8. Troubleshooting common errors
9. Security and production notes
10. Recommended follow-ups

## 1. Prerequisites
- Rust toolchain
  - Install latest stable Rust (rustup): https://rustup.rs/
  - Verify: `rustc --version` and `cargo --version`
- PostgreSQL
  - Version: any modern PostgreSQL (12+ recommended)
  - Tools: `psql`, `createdb`, `dropdb`, `pg_dump` (client utilities)
- Network ports
  - Default server bind: `0.0.0.0:3000` (changeable via `BIND_ADDRESS`)
- Optional: Docker (if you prefer running Postgres in Docker)

## 2. Environment variables
Set the following environment variables before running the server.

- `DATABASE_URL` (required)
  - Example: `postgres://user:password@localhost:5432/zcloudpass`
  - The server uses this to connect to Postgres.
- `BIND_ADDRESS` (optional)
  - Default: `0.0.0.0:3000`
  - Example: `0.0.0.0:3001` or `127.0.0.1:3000`

How to export (Linux/macOS sh)
```bash
export DATABASE_URL="postgres://user:password@localhost:5432/zcloudpass"
export BIND_ADDRESS="0.0.0.0:3000"
```

Windows PowerShell
```bash
$env:DATABASE_URL = "postgres://user:password@localhost:5432/zcloudpass"
$env:BIND_ADDRESS = "0.0.0.0:3000"
```

## 3. Database setup

### 3.1 Local Postgres
- Create a database and user if needed (example uses `createdb`):
```bash
createdb zcloudpass
# or with a specific owner:
# psql -c "CREATE DATABASE zcloudpass OWNER youruser;"
```

- Ensure your `DATABASE_URL` points to the created DB and that the user has privileges.

The server will run a lightweight schema creation routine (`ensure_tables`) on startup:
- Ensures `pgcrypto` extension (best-effort; will continue on failure with a notice).
- Creates `users` and `sessions` tables if they do not exist.

### 3.2 Dockerized Postgres
- Start a Postgres container:
```bash
docker run --name zcp-postgres -e POSTGRES_PASSWORD=password -e POSTGRES_USER=user -e POSTGRES_DB=zcloudpass -p 5432:5432 -d postgres:15
# Then set DATABASE_URL:
export DATABASE_URL="postgres://user:password@localhost:5432/zcloudpass"
```

## 4. Build and run (local)
- From repository root, change into the backend directory and run:

```bash
cd zcloudpass-backend
cargo build --release
# or run directly (development)
cargo run
```

- The server prints a "Server running on http://<bind>" message. If it binds to `0.0.0.0:3000`, you can visit or curl `http://localhost:3000/health` to confirm.

## 5. Resetting or clearing the database
Important: Always back up before destructive operations.

### 5.1 Backup (recommended)
- Create a dump before resetting:
```bash
pg_dump -Fc "$DATABASE_URL" -f zcloudpass-backup.dump
```

### 5.2 Full reset (drop + recreate database)
- This completely removes and recreates the database:
```bash
dropdb --if-exists zcloudpass
createdb zcloudpass
```
- Alternatively via `psql`:
```bash
psql postgres -c "DROP DATABASE IF EXISTS zcloudpass; CREATE DATABASE zcloudpass;"
```
- After recreating the DB, start the server; `ensure_tables` will create the needed tables.

### 5.3 Truncate tables (keep schema)
- If you only want to remove data and keep schema:
```bash
psql "$DATABASE_URL" -c "TRUNCATE TABLE sessions, users RESTART IDENTITY CASCADE;"
```

### 5.4 Drop tables (then let the server recreate them)
- Drop the two tables and run the server to recreate:
```bash
psql "$DATABASE_URL" -c "DROP TABLE IF EXISTS sessions CASCADE; DROP TABLE IF EXISTS users CASCADE;"
# then run the server (cargo run) to recreate
```

## 6. API usage examples (curl)
This project exposes the following relevant endpoints under `/api/v1`:

- `POST /api/v1/auth/register` — register a user
- `POST /api/v1/auth/session` — create a session (returns token)
- `GET /api/v1/vault/` — get encrypted vault (requires Authorization header)
- `PUT /api/v1/vault/` — update encrypted vault (requires Authorization header)

Assume `BASE=http://localhost:3000`.

### 6.1 Register a user
```bash
curl -s -X POST "$BASE/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","srp_salt":null,"srp_verifier":null,"encrypted_vault":null}'
```
Response: JSON with `id` and `email` on success. If the email already exists, the endpoint returns a conflict.

### 6.2 Create a session (get token)
```bash
curl -s -X POST "$BASE/api/v1/auth/session" \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'
```
Response: JSON `{ "session_token": "<token>", "expires_at": "..." }`

### 6.3 Get vault (requires Authorization: Bearer <token>)
```bash
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/vault/"
# returns: { "encrypted_vault": "<string|null>" }
```

### 6.4 Update vault
- Provide the entire encrypted blob (server stores opaque string).
```bash
curl -i -X PUT "$BASE/api/v1/vault/" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"encrypted_vault":"<BASE64_OR_OTHER_STRING>"}'
```

## 7. Postman and testing tips
- When importing a Postman collection, set `{{baseUrl}}` to `http://localhost:3000` (no trailing slash).
- After `Create Session`, store the returned `session_token` in an environment variable and use `Authorization: Bearer {{session_token}}` in subsequent requests.
- Ensure there is no trailing slash in the `baseUrl` environment variable; a trailing slash can produce `//` in the final URL and lead to 404s in some setups.

## 8. Troubleshooting common errors

- Connection refused or cannot connect to DB:
  - Verify `DATABASE_URL` is correct (host/port/database/user/password).
  - Ensure Postgres is running and accessible from where the backend runs.
  - If using Docker, ensure the container exposes the port and that host/port mapping is correct.

- 404 on `/api/v1/vault/`:
  - Confirm the server is running (curl `http://localhost:3000/health` and `http://localhost:3000/api/v1/auth/health`).
  - Check `baseUrl` for a trailing slash in Postman; remove trailing slash.
  - Ensure you are using the correct HTTP method: GET or PUT.

- 401 Unauthorized for vault endpoints:
  - Confirm the `Authorization` header format is `Authorization: Bearer <session_token>`.
  - Verify the token has not expired (sessions expire after one hour by default).
  - Verify the token exists in the `sessions` table and `expires_at` is in the future.

- SQLx errors during startup:
  - If the DB user lacks permission to create extensions (pgcrypto), the server will print a notice and continue; if you need pgcrypto, create it as a superuser:
    - `psql -d zcloudpass -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"`

- `create_session` returns token without password verification:
  - Note: current implementation creates session by email lookup and does not verify credentials. This is intended for development/test only.

## 9. Security and production notes (brief)
- Client-side encryption:
  - This backend stores an opaque `encrypted_vault` string. All encryption/decryption must happen on the client. The server never sees plaintext.
- Implement proper authentication:
  - Replace the current `create_session` behavior with a password verification (SRP or password hash + verification) before issuing tokens.
- Add optimistic concurrency:
  - Add a `vault_version` or `vault_etag` column to `users` to avoid clobbering concurrent updates.
- Limit sizes:
  - Enforce a maximum allowed size for `encrypted_vault` to prevent DoS and abuse.
- Session management:
  - Consider refresh tokens, revocation endpoints, and secure storage (cookies with HttpOnly/Secure for browser clients).
- Logging:
  - Avoid logging the `encrypted_vault` or any keys. Log only operational errors and non-sensitive metadata.

## 10. Recommended follow-ups
- Create a minimal `README.md` at repository root that links to this `INSTALLATION.md`. The README should contain a one-paragraph overview plus links to this file for installation and usage.
- Add a database migration strategy (e.g., `sqlx migrate`, `refinery`, or a dedicated migration folder).
- Implement proper authentication and add tests (integration tests for the API).
- Add optimistic locking support (return `vault_version` on GET and require it on PUT).
- Add rate limiting and request size checks (e.g., using `tower-http` or other middleware).

Appendix: Useful SQL snippets

- Add `vault_version` to `users` for optimistic locking:
```bash
ALTER TABLE users ADD COLUMN IF NOT EXISTS vault_version INT DEFAULT 0;
```

- Increment `vault_version` on update (example server-side update pseudocode):
```sql
UPDATE users
SET encrypted_vault = $1, vault_version = vault_version + 1, last_login = now()
WHERE id = $2 AND vault_version = $3;
-- check rows affected to detect conflicts
```
