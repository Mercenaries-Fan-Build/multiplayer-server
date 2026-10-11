# Multiplayer server image: builds `mp-server` in release mode and runs it as an unprivileged user.
#
#   docker build -t mp-server .
#   docker run --rm -v $PWD/config.toml:/etc/mp-server/config.toml:ro -v $PWD/relay:/etc/mp-server/relay:ro \
#       -v mp-data:/data -p 443:8443 -p 80:8080 -p 3659:3659/udp mp-server
#
# The container listens on unprivileged ports (8443 HTTPS, 8080 ACME HTTP-01, 3659/udp relay); map them to the
# public ports with -p / compose. Persistent state (SQLite database, ACME account + certificate) lives in /data.

FROM rust:1.94.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p mercs2_mp_server

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --home-dir /data --shell /usr/sbin/nologin mp \
 && mkdir -p /data /etc/mp-server \
 && chown mp:mp /data
COPY --from=build /src/target/release/mp-server /usr/local/bin/mp-server
USER mp
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8443/tcp 8080/tcp 3659/udp
ENTRYPOINT ["/usr/local/bin/mp-server"]
CMD ["--config", "/etc/mp-server/config.toml"]
