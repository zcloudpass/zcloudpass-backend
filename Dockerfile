# ── Builder stage ─────────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

WORKDIR /app

# Install build dependencies for native TLS (required by sqlx native-tls)
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create a dummy main to cache dependency builds
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "" > src/lib.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source and build
COPY src ./src
COPY tests ./tests
RUN touch src/main.rs src/lib.rs && \
    cargo build --release

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/zcloudpass-backend /usr/local/bin/zcloudpass-backend

ENV BIND_ADDRESS=0.0.0.0:3000

EXPOSE 3000

ENTRYPOINT ["zcloudpass-backend"]
