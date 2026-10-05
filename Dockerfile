# Stage 1: Build
FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies separately from source
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/evidence_export.rs && \
    echo "fn main() {}" > src/bin/irl_verify.rs && \
    echo "pub fn lib() {}" > src/lib.rs
RUN cargo build --release
RUN rm -rf src

# Build the actual source
COPY src ./src
COPY migrations ./migrations
RUN touch src/main.rs src/lib.rs && cargo build --release

# Stage 2: Runtime — debian-slim keeps the image small while providing
# glibc, libssl, and curl (needed for the Docker healthcheck).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root
RUN useradd -u 10001 -M -s /sbin/nologin appuser
USER appuser

WORKDIR /app

COPY --from=builder /app/target/release/irl-engine ./irl-engine
COPY --from=builder /app/migrations ./migrations

EXPOSE 4000

ENTRYPOINT ["./irl-engine"]
