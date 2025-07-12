# RUST BUILDER

FROM rust:1.87-bookworm AS builder
WORKDIR /usr/src/augesty

RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    pkg-config \
    cmake \
    clang \
    git \
    gcc \
    libsqlite3-dev

COPY . .
WORKDIR /usr/src/augesty/backend
ENV SQLX_OFFLINE=true
RUN cargo install --path .

# RUNNER

FROM debian:bookworm-slim
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      libssl3 libsqlite3-0 ca-certificates; \
    rm -rf /var/lib/apt/lists/*
ENV RUST_LOG="augesty=info"
COPY --from=builder /usr/local/cargo/bin/augesty /usr/local/bin/augesty
EXPOSE 8080
CMD ["augesty"]