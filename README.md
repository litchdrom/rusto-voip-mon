<p align="center">
  <img src="static/img/logo.svg" alt="rusto-voip-mon logo" width="240">
</p>

# rusto-voip-mon

An open-source web GUI for [VoIPmonitor](https://www.voipmonitor.org/), written in Rust.

- Read-only access to VoIPmonitor's MySQL/MariaDB database (CDRs, SIP messages)
- Position-based extraction of pcaps from VoIPmonitor's minute-bucketed `tar.zst` archives
- Single binary, single container, no PHP / ionCube / Apache

## Features (v0.1)

- Simple login that reuses VoIPmonitor's `users` table (legacy MD5 + modern bcrypt hashes supported)
- CDR list with filters: time range, caller, called, source IP, SIP response code, MOS range, sensor ID, duration
- Paginated CDR list with server-side filtering
- CDR detail page (basic fields; full SIP flow deferred to v0.2)
- CSV export
- PCAP single + batch download — *stubs in v0.1, implemented in v0.2*

## Quick start

### Build from source

```bash
cargo build --release
cp .env.example .env
# edit .env: set DATABASE_URL, APP_COOKIE_SECRET (openssl rand -hex 32)
./target/release/rusto-voip-mon
```

Open http://localhost:8080 and log in with your VoIPmonitor credentials.

### Run with Docker

```bash
cp .env.example .env
# edit .env
docker compose up -d
```

The image needs a read-only volume mount of `/var/spool/voipmonitor` from the
VoIPmonitor host. `docker-compose.yml` shows the wiring.

## Environment variables

| Name | Required | Default | Description |
|---|---|---|---|
| `LISTEN` | no | `0.0.0.0:8080` | HTTP bind address |
| `DATABASE_URL` | **yes** | — | `mysql://user:pass@host:3306/voipmonitor` |
| `PCAP_DIR` | no | `/var/spool/voipmonitor` | VoIPmonitor pcap spool root |
| `APP_COOKIE_SECRET` | **yes** | — | 32+ random bytes (`openssl rand -hex 32`) |
| `RUST_LOG` | no | `info` | standard tracing filter |

## Pcap storage layout (assumed)

```
{PCAP_DIR}/YYYY-MM-DD/HH/MM/{TYPE}/{TYPE}_YYYY-MM-DD-HH-MM.tar.zst
```

where `{TYPE}` is `SIP`, `RTP`, `GRAPH`, etc. The `cdr_tar_part` table
maps each CDR to a byte offset inside its minute's `tar.zst`. v0.2 will
stream extracts from these archives without ever loading a whole archive
into memory.

## Auth

Reuses VoIPmonitor's `users` table. Verified hashes:

- Legacy unsalted MD5 (32 hex chars) — what `admin/admin` ships with
- PHP `password_hash()` output (`$2y$...`, `$2a$...`, `$2b$...`) — bcrypt

A startup warning is logged if a user is still using the legacy MD5 hash.
Rotate the password through the upstream VoIPmonitor GUI to migrate.

Honored permission flags:

| `users` column | Used by rusto-voip-mon |
|---|---|
| `is_admin` | (reserved for v0.2 admin nav) |
| `can_cdr` | CDR list/detail access (default 1) |
| `can_pcap` | PCAP download endpoints (default 1) |
| `blocked`, `password_expired` | Login rejected if set |

## Project layout

```
src/
  main.rs           # bootstrap, router, cookie key
  config.rs         # env var loading
  state.rs          # AppState (config + db pool)
  db.rs             # MySQL pool
  error.rs          # AppError + IntoResponse
  auth/
    mod.rs
    password.rs     # dual MD5/bcrypt verification
    session.rs      # signed-cookie session (base64-url JSON)
  cdr/
    mod.rs          # CDR row type, filters, query builder
  routes/
    login.rs        # GET/POST /login, POST /logout
    cdr.rs          # GET /, GET /cdr/:id, GET /cdr/export.csv
    pcap.rs         # GET /pcap/:cdr_id, POST /pcap/batch (v0.2)
templates/
  base.html
  login.html
  cdr_list.html
static/
  css/style.css
  js/app.js
Dockerfile
docker-compose.yml
.env.example
```

## Roadmap

- **v0.1 (this version):** auth, CDR list + filters + pagination, CDR detail (basic), CSV export
- **v0.2:** batch PCAP download with position-based extraction from `cdr_tar_part`
- **v0.3:** SIP message flow on CDR detail page
- **v0.4:** MOS timeline + RTP stats chart, optionally swap to ECharts
- **v0.5:** sensor / collector status admin
- **v0.6+:** WAV playback, alerts, scheduled reports

## License

Dual-licensed under MIT or Apache-2.0, at your option.
