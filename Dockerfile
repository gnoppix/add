# Dockerfile for Add P2P Messenger
# Build: docker build -t add:latest .
# Run:   docker run --rm -it add:latest init

# ---- Build stage ----
FROM rust:1.96-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libsqlite3-dev \
    nettle-dev \
    libgmp-dev \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace Cargo files
COPY Cargo.toml Cargo.lock ./

# Copy per-crate Cargo.toml files
COPY protocol/Cargo.toml protocol/Cargo.toml
COPY crypto/Cargo.toml crypto/Cargo.toml
COPY crypto-utils/Cargo.toml crypto-utils/Cargo.toml
COPY dht-core/Cargo.toml dht-core/Cargo.toml
COPY p2p/Cargo.toml p2p/Cargo.toml
COPY client/Cargo.toml client/Cargo.toml
COPY relay/Cargo.toml relay/Cargo.toml
COPY bootstrap/Cargo.toml bootstrap/Cargo.toml

# Build dependencies only (cache layer)
RUN mkdir -p protocol/src crypto/src crypto-utils/src dht-core/src p2p/src client/src relay/src bootstrap/src \
    && echo '' > protocol/src/lib.rs \
    && echo '' > crypto/src/lib.rs \
    && echo '' > crypto-utils/src/lib.rs \
    && echo '' > dht-core/src/lib.rs \
    && echo '' > p2p/src/lib.rs \
    && echo 'fn main() {}' > client/src/main.rs \
    && echo 'fn main() {}' > relay/src/main.rs \
    && echo 'fn main() {}' > bootstrap/src/main.rs \
    && cargo build --release --workspace || true \
    && rm -rf target

# Copy actual source and build
COPY . .
RUN cargo build --release --workspace \
    && strip target/release/add target/release/add-relay target/release/add-bootstrap

# ---- Runtime stage ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libsqlite3-0 \
    libnettle8 \
    libhogweed6 \
    libgmp10 \
    libbz2-1.0 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash add \
    && mkdir -p /home/add/.add \
    && chown -R add:add /home/add

COPY --from=builder /app/target/release/add /usr/local/bin/
COPY --from=builder /app/target/release/add-relay /usr/local/bin/
COPY --from=builder /app/target/release/add-bootstrap /usr/local/bin/

RUN chmod 755 /usr/local/bin/add /usr/local/bin/add-relay /usr/local/bin/add-bootstrap

USER add
WORKDIR /home/add
VOLUME ["/home/add/.add"]

COPY docker-entrypoint.sh /usr/local/bin/entrypoint.sh
USER root
RUN chmod 755 /usr/local/bin/entrypoint.sh
USER add
ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
CMD ["add", "--help"]
