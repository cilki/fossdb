# Build from the workspace root, not from this directory:
#   docker build -f fossdb-server/Dockerfile .
#
# fossdb-server is a workspace member, so the whole workspace manifest and
# lockfile must be present for the build to resolve.
FROM rust:1 AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY fossdb ./fossdb
COPY fossdb-cli ./fossdb-cli
COPY fossdb-collector ./fossdb-collector
COPY fossdb-server ./fossdb-server
COPY fossdb-web ./fossdb-web
COPY fossdb-worker ./fossdb-worker

# Only the server and the CLI are needed in the image. fossdb-web targets
# wasm32 and is built separately.
RUN cargo build --release -p fossdb-server \
    && cargo build --release -p fossdb-cli --features admin

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/fossdb-server /usr/local/bin/fossdb-server
COPY --from=builder /app/target/release/fossdb /usr/local/bin/fossdb

# Database, and the directory holding the admin socket.
RUN mkdir -p /data /run/fossdb

ENV DATABASE_PATH=/data/fossdb.db
ENV SERVER_PORT=3000
ENV COLLECTOR_PORT=3001
ENV WORKER_PORT=3002
ENV ADMIN_SOCKET_PATH=/run/fossdb/admin.sock

# 3000 is the public API. 3001 and 3002 are the internal collector and worker
# APIs; they are guarded only by a shared API key, so do not publish them.
EXPOSE 3000

CMD ["fossdb-server", "serve"]
