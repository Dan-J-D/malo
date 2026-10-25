# syntax=docker/dockerfile:1
# Multi-stage build: Rust builder → distroless/cc, non-root, volume /data, port 8443.

FROM rust:1.92-bookworm AS builder
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

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /malo-server /malo-server
COPY --from=builder --chown=65532:65532 /data /data
USER 65532:65532
ENV MALO_LISTEN=0.0.0.0:8443 \
    MALO_DATA_DIR=/data \
    RUST_LOG=info
VOLUME ["/data"]
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/malo-server", "--healthcheck"]
ENTRYPOINT ["/malo-server"]
