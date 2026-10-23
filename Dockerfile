# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --bin grid --bin grid-mapbuild && \
    mkdir -p /out && cp target/release/grid target/release/grid-mapbuild /out/

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /data grid && mkdir -p /data && chown grid:grid /data
COPY --from=build /out/grid /out/grid-mapbuild /usr/local/bin/
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
USER grid
VOLUME /data
# libp2p (QUIC + TCP) and the local API
EXPOSE 4001/udp 4001/tcp 7777/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD curl -fs http://127.0.0.1:7777/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["run"]
