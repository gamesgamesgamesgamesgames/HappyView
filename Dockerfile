FROM rust:1.93 AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY migrations/ migrations/

ENV SQLX_OFFLINE=true
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false happyview

COPY --from=builder /app/target/release/happyview /usr/local/bin/happyview

USER happyview

EXPOSE 3000

ENTRYPOINT ["happyview"]
