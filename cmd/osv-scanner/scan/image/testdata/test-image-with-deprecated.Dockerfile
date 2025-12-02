FROM rust:latest AS builder

RUN cargo install cargo-auditable

WORKDIR /app
COPY test-image-with-deprecated/ .

# Build project with auditable as per doc
RUN cargo auditable build --release

FROM alpine:latest
COPY --from=builder /app/target/release/rust_novuln_deprecated /app/rust_novuln_deprecated
