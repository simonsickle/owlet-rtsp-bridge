# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS native
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY owlet-tutk/Cargo.toml owlet-tutk/Cargo.lock ./
COPY owlet-tutk/src ./src
RUN cargo build --locked --features dtls --release

FROM python:3.12-slim-bookworm AS base

ARG MEDIAMTX_VERSION=v1.21.4
ARG TARGETARCH

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/data \
    MEDIAMTX_BIN=/usr/local/bin/mediamtx

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ffmpeg curl ca-certificates tini libssl3 \
 && rm -rf /var/lib/apt/lists/*

# MediaMTX is the RTSP/WebRTC/HLS edge. Single static binary, no runtime deps.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) mt=amd64 ;; \
      arm64) mt=arm64 ;; \
      arm)   mt=armv7 ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/bluenviron/mediamtx/releases/download/${MEDIAMTX_VERSION}/mediamtx_${MEDIAMTX_VERSION}_linux_${mt}.tar.gz" \
      | tar -xz -C /usr/local/bin mediamtx; \
    chmod +x /usr/local/bin/mediamtx; \
    /usr/local/bin/mediamtx --version

WORKDIR /srv
COPY --from=native /build/target/release/owlet-tutk /usr/local/bin/owlet-tutk
COPY owlet-rtsp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY owlet-rtsp/app ./app

RUN useradd --system --uid 10001 --home /data owlet \
 && mkdir -p /data \
 && chown -R owlet:owlet /data

USER owlet
VOLUME ["/data"]
EXPOSE 8000 8554 8888 8889/tcp 8189/udp

HEALTHCHECK --interval=30s --timeout=4s --start-period=15s \
  CMD curl -fsS "http://127.0.0.1:${API_PORT:-8000}/api/health" | python -c 'import json, sys; sys.exit(not json.load(sys.stdin)["media"])'

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port \"${API_PORT:-8000}\" --proxy-headers"]
