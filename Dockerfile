# Build Stage
FROM rust:latest as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY admin ./admin
COPY .env .
COPY migrations ./migrations

ENV RUSTFLAGS="-C target-cpu=native"

RUN cargo build --release

# Production Stage
FROM rust:slim

WORKDIR /app

COPY --from=builder /app/target/release/leaf-opt-out .
COPY --from=builder /app/.env .
COPY --from=builder /app/migrations ./migrations

ENV RUST_ENV=production
ENV RUSTFLAGS="-C target-cpu=native"

CMD ["./leaf-opt-out"]