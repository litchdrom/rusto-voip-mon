<p align="center">
  <img src="static/img/logo.svg" alt="rusto-voip-mon logo" width="240"
       style="filter: drop-shadow(2px 1px 0 rgba(74, 158, 255, 0.45)) drop-shadow(0 0 4px rgba(74, 158, 255, 0.55)) drop-shadow(-2px -2px 12px rgba(74, 158, 255, 0.25)); transition: filter 0.15s ease-out;"
       onmouseover="this.style.filter='drop-shadow(2px 1px 0 rgba(74, 158, 255, 0.55)) drop-shadow(0 0 6px rgba(74, 158, 255, 0.70)) drop-shadow(-3px -3px 16px rgba(74, 158, 255, 0.35))';"
       onmouseout="this.style.filter='drop-shadow(2px 1px 0 rgba(74, 158, 255, 0.45)) drop-shadow(0 0 4px rgba(74, 158, 255, 0.55)) drop-shadow(-2px -2px 12px rgba(74, 158, 255, 0.25))';">
</p>

# rusto-voip-mon

An open-source web GUI for [VoIPmonitor](https://www.voipmonitor.org/), written in Rust.

- Read-only access to VoIPmonitor's MySQL/MariaDB database (CDRs, SIP messages)
- Position-based extraction of pcaps from VoIPmonitor's minute-bucketed `tar.zst` archives
- Single binary, single container, no PHP / ionCube / Apache

## Features

- **Auth**
  - Reuses VoIPmonitor's `users` table (legacy MD5 + modern bcrypt hashes)
  - Bearer tokens (`POST /auth/tokens`) for `curl` / CI / scripts — 90-day
    default TTL, list + revoke from the UI
- **CDR list** (`GET /`)
  - Filters: time range, caller / called (substring **or** exact multi-value
    IN-list), source / destination IP, SIP response code, MOS range, sensor
    ID, duration
  - Multi-page selection ("tick CDRs on pages 1–3, then download all in
    one zip"), per-operator TZ override, CSV export, distinct-value dropdowns
- **CDR detail** (`GET /cdr/:id`) — basic fields, `cdr_next` extension,
  call-leg table, SIP message timeline (colour-coded method + response
  code, direction arrow, raw SIP body behind a per-row toggle)
- **PCAP download**
  - `GET /pcap/:cdr_id` — single merged SIP + RTP pcap, streamed
    byte-for-byte from the minute's `tar.zst` (no full-archive load),
    VoIPmonitor's per-call LZO format decoded inline
  - `POST /pcap/batch` + `GET /pcap/batch?filter=...` — up to 100 pcaps
    zipped in one request; the zip carries a `cdrs.csv` sidecar with
    per-CDR metadata + a timezone note so the archive is self-
    documenting. GET form is the no-JS / `curl` / bookmark path; POST
    form is what the JS frontend uses.
- **Full HTTP API** documented in [`docs/API.md`](docs/API.md) — one curl
  example per endpoint, status-code table, "zero to API call" quickstart

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
| `DATABASE_URL` | **yes** | — | `mysql://user:pass@host:3306/voipmonitor` (read-only user recommended) |
| `PCAP_DIR` | no | `/var/spool/voipmonitor` | VoIPmonitor pcap spool root |
| `APP_COOKIE_SECRET` | **yes** | — | 32+ random bytes — `openssl rand -hex 32` |
| `CSV_EXPORT_LIMIT` | no | `10000` | Hard cap on rows per CSV download. Per-request override `?csv_limit=N`. |
| `APP_TZ_OFFSET_HOURS` | no | `0` | Shifts the default "today" filter window + label by N hours from UTC |
| `APP_QUERY_TIMEOUT_SECS` | no | `30` | Per-query DB timeout; `0` disables. On hit the client gets a 504. |
| `RUST_LOG` | no | `info` | Standard tracing filter — `rusto_voip_mon=debug` for verbose |

## Pcap storage layout (assumed)

```
{PCAP_DIR}/YYYY-MM-DD/HH/MM/{TYPE}/{TYPE}_YYYY-MM-DD-HH-MM.tar.zst
```

where `{TYPE}` is `SIP`, `RTP`, `GRAPH`, etc. The `cdr_tar_part` table
maps each CDR to a byte offset inside its minute's `tar.zst`. `rusto-voip-mon`
streams extracts via `zstd` + `tar` decoders without ever loading a whole
archive into memory, so a 1 GB minute's archive doesn't pin a 1 GB RSS.

PCAPs inside each archive come in two flavors:

- Raw `pcap` blobs (network byte order, linktype header at offset 20)
- VoIPmonitor's per-call LZO-compressed chunks
  (`LZO` 3-byte magic, then repeated `[u32 size][u32 compress_size][…]`
  frames). `rusto-voip-mon` decodes both inline and merges the packets
  from SIP + RTP archives into a single time-ordered pcap per CDR.

## Auth

Reuses VoIPmonitor's `users` table. Verified hashes:

- Legacy unsalted MD5 (32 hex chars) — what `admin/admin` ships with
- PHP `password_hash()` output (`$2y$...`, `$2a$...`, `$2b$...`) — bcrypt

A startup warning is logged if a user is still using the legacy MD5 hash.
Rotate the password through the upstream VoIPmonitor GUI to migrate.

Honored permission flags:

| `users` column | Used by rusto-voip-mon |
|---|---|
| `is_admin` | Superuser — implies `can_cdr` and `can_pcap`. Admin rows get full access even if the per-feature columns are NULL. |
| `can_cdr` | CDR list / detail access. NULL or `0` → 403 on `/` and `/cdr/:id`. |
| `can_pcap` | PCAP download endpoints. NULL or `0` → 403 on `/pcap/:id` and `/pcap/batch`. |
| `blocked`, `password_expired` | Login rejected if either is set. |

## Project layout

```
src/
  main.rs           # bootstrap, router, middleware wiring
  config.rs         # env var loading
  state.rs          # AppState (config + db pool + token store)
  db.rs             # MySQL pool
  error.rs          # AppError + IntoResponse
  middleware.rs     # request logging, trace IDs
  auth/
    mod.rs
    password.rs     # dual MD5/bcrypt verification + verify_login()
    session.rs      # signed-cookie session (base64-url JSON + HMAC)
    token.rs        # bearer-token store (in-memory, HMAC-signed ids)
  cdr/
    mod.rs          # CDR row + filters + WHERE-clause builder
  routes/
    mod.rs
    login.rs        # GET/POST /login, POST /logout, POST /tz
    auth.rs         # POST/GET/DELETE /auth/tokens
    cdr.rs          # GET /, GET /cdr/:id, GET /cdr/export.csv, POST /cdr/select
    pcap.rs         # GET /pcap/:cdr_id, POST /pcap/batch (streaming)
templates/
  base.html         # shell, topbar, TZ dropdown, token list
  login.html
  cdr_list.html     # checkbox + batch download + filter form
  macros.html       # shared form-field macros
static/
  css/style.css
  js/app.js         # selection persistence, batch POSTs, filter debouncing
  img/
    logo.svg        # canonical — glow filter baked in for dark themes
    logo-glow.png   # transparent PNG fallback for non-SVG contexts
docs/
  API.md            # full HTTP API reference
Dockerfile          # multi-stage build (rust:1.83 → debian:bookworm-slim)
docker-compose.yml  # example wiring against existing voipmonitor host
.env.example        # every env var with safe defaults
```

## Roadmap

- **Shipped**
  - Auth (MD5 + bcrypt), CDR list + filters + pagination, CDR detail (basic), CSV export
  - Single + batch PCAP download (position-based extraction from `cdr_tar_part`,
    VoIPmonitor LZO format decoded inline, merged SIP+RTP pcap output)
  - Cross-page batch selection + filter-mode batch download
  - Bearer-token auth + `docs/API.md`
  - Multi-value caller / called search (`caller_in`, `called_in` SQL IN-list)
  - Brand-glow logo baked into the SVG for dark-theme legibility
  - Admin override (`is_admin` implies all per-feature permissions)
- **Next**
  - MOS timeline + RTP stats chart on CDR detail
  - Optional `<noscript>` apply-button polish
- **Later**
  - WAV playback (chunked streaming from `sip_msg.rtp_payload_data`)
  - Per-user RBAC UI (currently DB-only)
  - Sensor / collector status admin
  - Alerts, scheduled reports

## License

Dual-licensed under MIT or Apache-2.0, at your option.
