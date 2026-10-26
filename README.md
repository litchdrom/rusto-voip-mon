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
  call-leg table, **per-leg RTP statistics** (MOS LQO, codec + ptime,
  packet loss + %, avg/max jitter, one-way delay, RTCP cumulative
  loss + max jitter), SIP message timeline (colour-coded method +
  response code, direction arrow, raw SIP body behind a per-row
  toggle). Tries the `sip_msg` table first; falls back to parsing
  the SIP messages out of the merged pcap archive (with
  `etherparse`) when the table is empty or schema-mismatched.
- **Call audio** — `GET /cdr/:id/audio.wav?leg=a|b` reconstructs the
  recording from the on-disk pcap and serves it as WAV. G.711 µ-law
  and A-law are decoded in-process (8 kHz mono 16-bit PCM); packets
  lost in transit are gap-filled with silence so the playback speed
  is right. The detail page renders a player per G.711 leg — legs on
  other codecs get no player rather than a dead button.
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

### Cross-compile for Linux from Windows

You don't need WSL or a Linux VM. [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild)
drives the Zig C toolchain to cross-compile, so a Windows dev box can produce the
same static-ish Linux binary the Dockerfile builds.

One-time setup (PowerShell):

```powershell
rustup target add x86_64-unknown-linux-gnu
cargo install cargo-zigbuild
winget install zig.zig            # or: scoop install zig
```

Restart your shell so `zig` lands on `PATH`, then:

```powershell
cargo zigbuild --release --target x86_64-unknown-linux-gnu
# -> target\x86_64-unknown-linux-gnu\release\rusto-voip-mon
```

Deploy the artifact and restart the service:

```powershell
scp target\x86_64-unknown-linux-gnu\release\rusto-voip-mon user@server:/usr/local/bin/rusto-voip-mon
ssh user@server sudo systemctl restart rusto-voip-mon
```

The binary embeds its own build stamp — `--version` prints the commit it was
built from, so a stale upload is obvious:

```
$ ./rusto-voip-mon --version
rusto-voip-mon 0.1.0 (commit <sha>, built <rfc3339>)
```

| Item | Notes |
|---|---|
| Target | `x86_64-unknown-linux-gnu` — the same target `Dockerfile` builds. For ARM servers use `aarch64-unknown-linux-gnu` instead. |
| `zig` on `PATH` | `cargo-zigbuild` shells out to it. If `zig version` fails in a fresh shell, the install didn't pick up your profile. |
| Runtime deps | The Linux host still needs `libssl3`, `ca-certificates`, and `zstd` (see the `runtime` stage in `Dockerfile`). The binary itself is self-contained. |
| `templates/` | Baked into the binary by `askama` at compile time — no need to ship it. `askama`'s derive registers every `templates/*.html` as a build dependency, so editing one triggers a recompile on its own. No `cargo clean` needed. |
| `static/` | **Read from disk at runtime** via `ServeDir::new("static")`, resolved relative to the process CWD. Keep a `static/` directory next to wherever you run the binary from. |

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
| `APP_TZ_OFFSET_SECS` | no | `0` | Default operator-display TZ (seconds from UTC). Shifts the "today" window, label, and per-operator fallback. Whole-hour zones: `28800` for UTC+8, `-18000` for UTC-5. Half/quarter-hour zones also supported: `19800` for IST (UTC+5:30), `20700` for Nepal (UTC+5:45), `45900` for Chatham (UTC+12:45). Range `-43200..=50400`. Operators can override per-session from the topbar TZ selector. |
| `APP_DB_TZ_OFFSET_SECS` | no | `0` | TZ offset, in **seconds**, of the **stored** `calldate` values in the VoIPmonitor DB. Default 0 because the standard VoIPmonitor convention is to store `DATETIME` in UTC. Set non-zero only when your MySQL session is configured for server-local time (e.g. `19800` for IST +5:30 storage, `28800` for UTC+8 wall-clock, `-18000` for US Eastern). Range `-43200..=50400`. Conversion is applied at the SQL→view boundary so all displayed times are in the operator's chosen TZ; the inverse shift is applied at the filter-bind layer so naive `from`/`to` filter bounds stay in operator-TZ semantics end-to-end. |
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
  - Auth (MD5 + bcrypt), CDR list + filters + pagination, CDR detail, CSV export
  - Single + batch PCAP download (position-based extraction from `cdr_tar_part`,
    VoIPmonitor LZO format decoded inline, merged SIP+RTP pcap output)
  - Cross-page batch selection + filter-mode batch download
  - Bearer-token auth + `docs/API.md`
  - Multi-value caller / called search (`caller_in`, `called_in` SQL IN-list)
  - Brand-glow logo baked into the SVG for dark-theme legibility
  - Admin override (`is_admin` implies all per-feature permissions)
  - Per-operator timezone selector (seconds precision, half/quarter-hour zones),
    with a server-side default and an optional DB-storage offset
  - UDP source/destination port filters on the first INVITE
    (`cdr.sipcallerport` / `cdr.sipcalledport`, multi-value), plus the same
    ports shown as columns in the CDR list
  - MOS timeline + RTP stats chart on CDR detail (`GET /cdr/:id/rtp-chart.json`,
    per-leg jitter / MOS / loss / jitter / one-way delay from the on-disk RTP pcap)
  - sngrep-style call-flow diagram on CDR detail (phase boxes, proportional
    widths, worst-response-code colouring)
  - SIP message timeline sourced from the merged pcap archive when available,
    falling back to `sip_msg`; raw SIP body expands into a full-width row
  - Per-user RBAC UI (`/admin/users` — create, edit, reset password, delete,
    with self-lockout protection)
  - Sensor / collector admin UI (`/admin/sensors` — CRUD over
    `sensors` / `sensor_stats`)
  - `<noscript>` fallbacks for every JS-only control (Apply button always
    visible, batch download, TZ apply, reset-to-today)
- **Next**
  - Audio playback for codecs beyond G.711 (G.729 / Opus need a real
    decoder and a container the browser can play)
- **Later**
  - Alerts, scheduled reports

## License

Dual-licensed under MIT or Apache-2.0, at your option.
