# syntax=docker/dockerfile:1.7

# ----- builder -----
FROM rust:1.83-bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Cache deps first
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src templates static \
 && echo 'fn main() {}' > src/main.rs \
 && cargo build --release \
 && rm -rf src target/release/rusto-voip-mon target/release/deps/rusto_voip_mon-*

# Build the real thing
COPY src ./src
COPY templates ./templates
COPY static ./static
RUN touch src/main.rs && cargo build --release

# ----- runtime -----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 zstd \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /app --shell /usr/sbin/nologin rusto

WORKDIR /app
COPY --from=builder /app/target/release/rusto-voip-mon /usr/local/bin/rusto-voip-mon
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static    ./static

USER rusto
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/rusto-voip-mon"]
