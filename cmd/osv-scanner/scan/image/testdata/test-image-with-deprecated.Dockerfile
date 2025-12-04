FROM rust:latest AS builder

RUN cargo install cargo-auditable

WORKDIR /app
COPY test-image-with-deprecated/ .

# Build project with auditable as per doc
RUN cargo auditable build --release

FROM alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412
COPY --from=builder /app/target/release/rust_novuln_deprecated /app/rust_novuln_deprecated
