# Build stage
FROM rust:1.91-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin botwhisper

# Runtime stage: small Debian image with CA certificates for outbound
# doorbell webhooks. (A distroless/static musl image is on the Phase 2 list.)
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data botwhisper \
 && mkdir -p /data && chown botwhisper:botwhisper /data
COPY --from=build /src/target/release/botwhisper /usr/local/bin/botwhisper
USER botwhisper
VOLUME ["/data"]
ENV BW_BIND=0.0.0.0:9100 \
    BW_DATA=/data/botwhisper.sqlite3
EXPOSE 9100
ENTRYPOINT ["botwhisper"]
CMD ["relay"]
