# mp-server — Mercenaries 2 multiplayer server

The server half of the multiplayer rewrite. The game-side ASI terminates FESL/Theater locally and talks to this
server through the `mercs2_mp_api` contract (`crates/mercs2_mp_api`):

| Endpoint | Transport | Purpose |
|---|---|---|
| `POST /v1/accounts` | HTTPS | create an account (argon2id password hash) |
| `POST /v1/sessions` | HTTPS | log in, get a bearer token (only its sha256 is stored) |
| `GET /v1/ws` | WebSocket over HTTPS, `Authorization: Bearer <token>` | lobby: games, joins, friends, stats, pushes |
| relay | UDP, DTLS 1.2 | gameplay/voice datagrams between the players of one game |

Games live in memory only; accounts, sessions, friends and stats live in SQLite (`database.path`).

Game privacy uses room keys (`mercs2_mp_api::ws::Privacy`). A host may set an optional `room_key` (6–32 ASCII letters,
digits or `-`, compared case-sensitively); keys are not unique, so any number of live games may share one. A client
listing, fetching or joining games presents its own optional `room_key` and reaches only games hosted with exactly
that key — or, without a key, only keyless games. A keyed game asked for with the wrong or no key answers
`not_found`. `friends_only` applies on top: such a game is reachable only by the host's mutual friends.

## Configuration

`mp-server --config <file>` — the only argument. Start from `config.example.toml`. Every key is required and
unknown keys are rejected; the process exits non-zero with the offending key named if anything is missing or
invalid. `tls.mode` has no default: pick `acme` or `proxied`.

The relay certificate may be self-signed. The server computes its sha256 and hands it to each client in the
relay assignment; the client pins it. Generate one with:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout relay/key.pem -out relay/cert.pem -days 3650 -subj /CN=mp-relay
```

Replacing the relay certificate changes the fingerprint; clients receive the new one on their next game.

## Deploy on a VM with a public IP (TLS mode `acme`)

The server obtains and renews its own certificate with the ACME HTTP-01 challenge, so port 80 must reach it.

1. Point a DNS `A`/`AAAA` record (e.g. `mp.example.com`) at the VM (a DigitalOcean droplet or similar).
2. Open the firewall: TCP 80, TCP 443, UDP 3659.
3. Create `config.toml` from `config.example.toml` with the `mode = "acme"` table:
   - `domains = ["mp.example.com"]`, `contact_email`, `relay.public_host = "mp.example.com"`.
   - `directory_url`: start with Let's Encrypt **staging**
     `https://acme-staging-v02.api.letsencrypt.org/directory`; once that issues, switch to **production**
     `https://acme-v02.api.letsencrypt.org/directory` (the account file is kept per directory URL, so
     switching creates a fresh production account). `directory_ca = "system"`.
   - `http_listen = "0.0.0.0:8080"`, `https_listen = "0.0.0.0:8443"` (the image's unprivileged ports).
4. Create the relay certificate next to `compose.yaml` (mounted at `/etc/mp-server/relay`), then start:

```sh
mkdir -p relay && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout relay/key.pem -out relay/cert.pem -days 3650 -subj /CN=mp-relay
chmod 0644 relay/key.pem   # the container runs as uid 10001 and must read it; restrict the directory instead
docker compose up -d --build
docker compose logs -f mp-server
```

On first start the server registers an ACME account, answers the HTTP-01 challenge and only then
opens HTTPS. The certificate is renewed `renew_before_days` before expiry and swapped in without a restart; a
failed renewal is retried every `retry_interval_secs` and the server exits if the certificate actually
expires. The account key, certificate and key are kept in `cache_dir` (mode 0600).

## Deploy behind Traefik (TLS mode `proxied`)

Traefik terminates the public HTTPS with its own Let's Encrypt resolver and forwards to the server's HTTPS
listener, which presents a self-signed certificate that Traefik is told not to verify. DTLS cannot be
terminated by Traefik; the relay always terminates it itself, so UDP is either published straight from the
container or passed through a Traefik UDP entrypoint untouched.

Server `config.toml` (`[tls]` table):

```toml
[tls]
mode = "proxied"
cert_pem = "/etc/mp-server/https/cert.pem"   # self-signed (openssl command above, -subj /CN=mp-server);
key_pem = "/etc/mp-server/https/key.pem"     # mount ./https there (commented line in compose.yaml)
trusted_proxies = ["172.18.0.0/16"] # the Docker network Traefik reaches the server on
```

Client IPs (used for rate limiting and logs) come from `X-Forwarded-For` only when the TCP peer is inside
`trusted_proxies`; such requests must carry the header (Traefik adds it), others are attributed to the peer.

Traefik dynamic configuration (file provider):

```yaml
http:
  routers:
    mp:
      rule: "Host(`mp.example.com`)"
      entryPoints: [websecure]
      service: mp
      tls:
        certResolver: letsencrypt
  services:
    mp:
      loadBalancer:
        serversTransport: mp-selfsigned
        servers:
          - url: "https://mp-server:8443"
  serversTransports:
    mp-selfsigned:
      insecureSkipVerify: true

udp:
  routers:
    mp-relay:
      entryPoints: [mp-relay]
      service: mp-relay
  services:
    mp-relay:
      loadBalancer:
        servers:
          - address: "mp-server:3659"
```

Static configuration additions for the UDP entrypoint (only if the relay goes through Traefik):

```yaml
entryPoints:
  mp-relay:
    address: ":3659/udp"
    udp:
      timeout: 120s   # must exceed relay.idle_timeout_secs, or Traefik drops quiet sessions first
```

WebSocket upgrades pass through the HTTP router unchanged. Simplest alternative for the relay: skip the UDP
entrypoint and publish `3659:3659/udp` on the mp-server container directly. Either way set
`relay.public_host`/`relay.public_port` to what clients reach. In `proxied` mode the container does not need
port 80, and `https_listen` should not be published publicly (Traefik reaches it on the Docker network).

## Relay behaviour

- One DTLS 1.2 association per client address, all on one UDP socket. HelloVerifyRequest cookies (HMAC of the
  source address) are required before the server sends its certificate; handshakes in progress are capped
  (`max_pending_handshakes`) and time out (`handshake_timeout_secs`).
- The first application datagram must be `Hello{token}` with a token issued to that user for that game.
  `Data{slot}` is then delivered to the player in that slot of the same game, with `slot` rewritten to the
  sender's. Data before `Hello`, unknown tokens/slots/channels and malformed datagrams are dropped, counted and
  logged; nothing unauthenticated is forwarded.
- Associations are closed (DTLS close_notify) when the player leaves or the game is removed, and after
  `idle_timeout_secs` without traffic. Clients learn that timeout in `RelayAssignment.idle_timeout_secs` and
  send `Keepalive` (a one-byte datagram, accepted only after `Hello`) while their game is quiet.
- A join request is given the joiner's PID when it is made (`JoinRequest.pid`), and acceptance keeps it, so the
  host's EGRQ and the joiner's EGEG carry the same PID, as the game's own LAN Theater does.

## Players per game

`[games] max_players_limit` caps the `max_players` a host may ask for; the shipped `config.example.toml` sets it
to 2. More than 2 players needs clients that relay joiner-to-joiner traffic (a mesh) — the current
`multiplayer_restored` ASI links only host↔joiner. It enforces that limit itself: its host answers a join
request that arrives while it already has a joiner (accepted or awaiting its answer) with
`join_respond { allowed: false, reason: mesh_unsupported }`, and its joiner fails the Theater connection on a
`JoinAccepted.players` above 2.

## Join-deny reasons

Denials carry a typed `JoinDenyReason`, never free text; the joiner's ASI maps it to the `REASON` of the game's
`'jden'` EGEG (evidence: `docs/reverse_engineer/multiplayer_rewrite_re.md`, join-deny reasons).

| reason | sent by | game `REASON` |
|---|---|---|
| `host_denied { code }` | host (its game's EGRS `REASON`, an integer) | `code`, verbatim |
| `mesh_unsupported` | host ASI (second joiner) | `f` |
| `game_removed` | server (host closed/left while the request was pending) | `c` |

`games_join` itself fails with `game_full` (no free slot; the ASI answers EGAM `'jden'` `REASON=f`),
`game_closed` (closed to joins; `REASON=c`) or `not_found` (`'ngam'`).

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
docker build -t mp-server .
```

The integration tests (`crates/mercs2_mp_server/tests/server.rs`) start the server in-process in `proxied` mode on
ephemeral ports with freshly generated self-signed certificates and drive REST, WebSocket and the DTLS relay.

ACME against a local test CA: run [Pebble](https://github.com/letsencrypt/pebble)
(`docker run -p 14000:14000 ghcr.io/letsencrypt/pebble`), set `directory_url = "https://localhost:14000/dir"`,
`directory_ca` to Pebble's `test/certs/pebble.minica.pem`, `domains = ["host.docker.internal"]` and
`http_listen = "0.0.0.0:5002"` (Pebble's default HTTP-01 port).
