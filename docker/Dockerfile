# syntax=docker/dockerfile:1
# Multi-stage build: Rust builder → distroless/cc, non-root, volume /data, ports 8443 (API), 1993/1465 (IMAP/SMTP when enabled).

FROM rust:1.92-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2 AS builder
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends perl make && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Build only the server crates (the desktop app isn't part of the image).
RUN sed -i 's/, "src-tauri"//' Cargo.toml
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p malo-server && cp target/release/malo-server /malo-server
RUN mkdir -p /data && chown 65532:65532 /data

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=builder /malo-server /malo-server
COPY --from=builder --chown=65532:65532 /data /data
USER 65532:65532
ENV MALO_LISTEN=0.0.0.0:8443 \
    MALO_DATA_DIR=/data \
    RUST_LOG=info
VOLUME ["/data"]
EXPOSE 8443 1993 1465
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/malo-server", "--healthcheck"]
ENTRYPOINT ["/malo-server"]
