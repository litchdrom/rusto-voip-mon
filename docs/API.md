# rusto-voip-mon HTTP API

This document is the canonical reference for every HTTP endpoint exposed
by rusto-voip-mon. Every example is a `curl` one-liner you can run as-is
against a live instance (replace `$HOST` with your server URL and
`$TOKEN` with a bearer token — see the auth section below).

The same endpoints also work from a browser — the login form sets a
signed cookie and the JS on the CDR list / detail pages uses `fetch()`
with the cookie implicit. The bearer-token variant below is the same
request but with `Authorization: Bearer …` instead.

## Conventions

- **Base URL**: assume `http://localhost:8080`; use HTTPS in production.
- **Content types**:
  - Request: `application/json` unless noted (form fields use
    `application/x-www-form-urlencoded`).
  - Response: depends on the endpoint; `application/json`,
    `text/csv`, `application/vnd.tcpdump.pcap`, or `application/zip`.
- **Errors**: JSON `{"error": "..."}` with an appropriate 4xx / 5xx
  status code. The auth endpoints return plain text.
- **Timestamps** in responses are naive (`YYYY-MM-DD HH:MM:SS`) in the
  server's configured timezone (override per-user via the topbar
  dropdown, see `POST /tz` below).
- **Auth**: every endpoint except `/login`, `/healthz`, `/static/*`
  requires a session. Either:
  - A signed `Cookie: <COOKIE_NAME>=<payload>.<hmac>` set by `/login`, OR
  - An `Authorization: Bearer <id>.<hmac>` token issued by
    `POST /auth/tokens` (long-lived, recommended for scripts / CI).

---

## Health

### `GET /healthz`

Liveness probe for orchestrators. Returns the literal string `ok` with
`200 OK` as long as the process is running. Does not touch the database.

```bash
curl -fsS $HOST/healthz
# → ok
```

---

## Authentication

### `GET /login`

Renders the login form. No auth required.

```bash
curl -fsS $HOST/login
# → HTML page
```

### `POST /login`

Browser login. Form-encoded `username` + `password` (and optional `next`
for the redirect target). On success, sets the session cookie and
redirects to `next` or `/`.

```bash
curl -fsS -c cookies.txt -X POST $HOST/login \
     -d 'username=admin' -d 'password=admin' -d 'next=/'
# → 302 redirect, Set-Cookie: rusto_session=…
```

### `POST /logout`

Invalidates the current session. Always returns 302 → `/login` and
clears the cookie.

```bash
curl -fsS -b cookies.txt -X POST $HOST/logout
```

### `POST /tz`

Update the per-user timezone override (the topbar dropdown). Form
fields:

| Field | Type | Notes |
|---|---|---|
| `tz_offset_hours` | integer `-12..14` | `0` clears the override |
| `next` | relative URL | redirect target (defaults to `/`) |

```bash
curl -fsS -b cookies.txt -X POST $HOST/tz \
     -d 'tz_offset_hours=-3' -d 'next=/?from=2026-09-25&to=2026-09-25'
```

### `POST /auth/tokens`

Exchange `username` + `password` for a long-lived bearer token. Use
this for scripts / CI / `curl` workflows — single `Authorization: Bearer …`
header works on every protected endpoint from then on.

Request body:

```json
{
  "username": "admin",
  "password": "...",
  "label": "CI deploy",
  "ttl_seconds": 7776000
}
```

| Field | Required | Notes |
|---|---|---|
| `username` | yes | |
| `password` | yes | |
| `label` | no | human-readable, shown in `GET /auth/tokens` |
| `ttl_seconds` | no | default 90 days, clamped to `[60, 5 years]` |

Response 200:

```json
{
  "token": "abc123…64hex…def456.hmac64hex",
  "expires_at": 1234567890
}
```

```bash
# Issue a 30-day CI token
curl -fsS -X POST $HOST/auth/tokens \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"admin","label":"prod-deploy","ttl_seconds":2592000}'
# → {"token":"...","expires_at":1234567890}
```

Save the token somewhere (1Password, vault, `.netrc`-equivalent) — the
server only stores the metadata, not the token itself, and the token is
never returned again after this endpoint.

### `GET /auth/tokens`

List your own active tokens. Returns metadata only — never the token
value. Response 200: `[{id, label, created_at, expires_at}, …]`.

```bash
curl -fsS -H "Authorization: Bearer $TOKEN" $HOST/auth/tokens
```

### `DELETE /auth/tokens/:id`

Revoke one of your tokens by its id. Returns 204 on success, 404 if the
id is unknown or belongs to another user (no enumeration leak).

```bash
curl -fsS -X DELETE -H "Authorization: Bearer $TOKEN" \
     $HOST/auth/tokens/abc123…64hex…
```

---

## CDR list / detail

### `GET /`

Paginated, filtered CDR list. Every query parameter is optional; the
defaults give "today's CDRs, page 1, 50 per page".

| Query param | Type | Notes |
|---|---|---|
| `from` | `YYYY-MM-DDTHH:MM` | local time (uses `APP_TZ_OFFSET_HOURS` or session TZ) |
| `to` | same | exclusive |
| `caller`, `called` | substring | case-insensitive `LIKE %…%` |
| `src_ip`, `dst_ip` | CSV | repeated keys OR comma-separated |
| `sip_code` | CSV | e.g. `486,487,503` |
| `mos_min`, `mos_max` | `0.0 .. 5.0` | |
| `duration_min`, `duration_max` | seconds | |
| `id_sensor` | CSV | VoIPmonitor sensor IDs |
| `page` | integer | default 1 |
| `page_size` | integer | default 50, max 500 |
| `tz_offset_hours` | `-12..14` | overrides session TZ for this URL only |

```bash
# Today's failed calls (4xx/5xx) with bad MOS
curl -fsS -b cookies.txt "$HOST/?from=2026-09-25T00:00&to=2026-09-25T23:59&sip_code=4,sip_code=5&mos_max=3.0" \
  | head -c 2000
```

The same query string also powers the CSV export, the new "all matching"
batch-PCAP download, and the pre-fetched adjacent pages in the
topbar's pagination.

### `GET /cdr/:id`

CDR detail. Renders an HTML page with the call's basic fields + a
placeholder for the SIP flow (deferred to v0.3).

```bash
curl -fsS -b cookies.txt $HOST/cdr/3407244
```

### `GET /cdr/export.csv`

Stream the matching CDRs as CSV. Same filter params as `/`. Output
columns: `id, calldate, callend, duration, caller, called,
last_sip, mos, id_sensor`. Capped by `CSV_EXPORT_LIMIT` (10,000 by
default; per-request `?csv_limit=N` overrides).

```bash
curl -fsS -b cookies.txt "$HOST/cdr/export.csv?from=2026-09-25T00:00&to=2026-09-25T23:59" \
  -o cdrs.csv
```

### `POST /cdr/select`

Persist the operator's batch-download selection across page navigation.
JS on the CDR list page POSTs the full current selection on every
checkbox toggle (debounced 400ms); the response carries a refreshed
session cookie.

Request body: `{"ids": [3407244, 3407245, ...]}`. Returns `204 No Content`.
Capped at 100 ids per session (oldest dropped, latest kept).

```bash
curl -fsS -b cookies.txt -c cookies.txt -X POST $HOST/cdr/select \
     -H 'Content-Type: application/json' \
     -d '{"ids":[3407244,3407245]}'
```

---

## PCAP download

Both endpoints stream via `tokio::sync::mpsc` + `Body::from_stream` —
the response starts as soon as the first bytes are ready, no buffering
the whole pcap in memory.

### `GET /pcap/:cdr_id`

Stream the merged SIP + RTP pcap for one CDR. Output is a single
`application/vnd.tcpdump.pcap` file (~10 KB–1 MB depending on call
length). Internally:

1. Look up `cdr_tar_part` for byte offsets into the minute's tar.zst
   archive.
2. Fall back to scanning by `cdr_next.fbasename` (the per-call pcap
   filename) when no byte offsets are indexed.
3. zstd-decompress the tar, extract the inner pcaps, strip per-call
   pcap global headers (every chunk after the first).
4. LZO-decompress VoIPmonitor's per-call RTP blobs (the
   `LZO`-prefixed chunks).
5. Merge into a single sorted-by-timestamp pcap.

```bash
curl -fsS -b cookies.txt $HOST/pcap/3407244 -o cdr-3407244.pcap
wireshark cdr-3407244.pcap
```

### `POST /pcap/batch`

Zip up to 100 pcaps into one archive. Two modes — exactly one of
`ids` or `filter` per request.

#### `ids` mode — per-row selection

Request body:

```json
{ "ids": [3407244, 3407245, 3407246] }
```

Response: `application/zip`, one entry per CDR named `cdr-<id>.pcap`.

```bash
curl -fsS -X POST $HOST/pcap/batch \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"ids":[3407244,3407245,3407246]}' \
     -o pcaps.zip
unzip -l pcaps.zip
# → cdr-3407244.pcap
# → cdr-3407245.pcap
# → cdr-3407246.pcap
```

Duplicates are collapsed; ids <= 0 are dropped; > 100 ids returns
`400 Bad Request`.

#### `filter` mode — "download all matching"

Powers the **Download zip of all matching pcaps** button next to
"Export CSV" on the list page. The server parses `filter` the same way
it parses the list-page query string and resolves it to all matching
CDRs (capped at 100).

Request body:

```json
{ "filter": "from=2026-09-25T00:00&to=2026-09-25T23:59&mos_max=3.0&sip_code=4&sip_code=5" }
```

`filter` is a raw `application/x-www-form-urlencoded` body without the
leading `?`. The same field names accepted by `GET /` work here.

```bash
# Every bad-MOS call in the last 24h, zipped
curl -fsS -X POST $HOST/pcap/batch \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"filter":"from=2026-09-24T00:00&to=2026-09-25T00:00&mos_max=3.0"}' \
     -o bad-mos.zip
unzip -l bad-mos.zip | head
```

#### Response codes

| Code | Meaning |
|---|---|
| `200 OK` | zip archive (even if some CDRs failed — failed entries are logged and skipped) |
| `400 Bad Request` | neither `ids` nor `filter`, both empty, > 100 ids, or filter matched 0 CDRs |
| `401 Unauthorized` | no valid session cookie or bearer token |
| `403 Forbidden` | user has `can_pcap = 0` |

---

## Status / limits

- Query timeout: every DB call is wrapped in `with_query_timeout`
  (`APP_QUERY_TIMEOUT_SECS`, default 30s). On timeout, the affected
  endpoint returns `504 Gateway Timeout`.
- CSV export: `CSV_EXPORT_LIMIT` (default 10,000 rows); per-request
  `?csv_limit=N` overrides.
- PCAP batch: 100 CDRs per request (single pcap download has no cap).
- API tokens: default 90-day lifetime, max 5 years.

## Quickstart: from zero to API call

```bash
# 1. Start the server (see README.md for env config)
cargo run --release

# 2. Get a bearer token (one-time per script)
TOKEN=$(curl -fsS -X POST http://localhost:8080/auth/tokens \
            -H 'Content-Type: application/json' \
            -d '{"username":"admin","password":"admin","label":"my-script"}' \
        | jq -r .token)

# 3. Use it on every protected endpoint
curl -fsS -H "Authorization: Bearer $TOKEN" \
     "http://localhost:8080/?from=2026-09-25T00:00&to=2026-09-25T23:59" \
  | head -c 2000

# 4. Bulk-download matching pcaps
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"filter":"from=2026-09-25T00:00&to=2026-09-25T23:59&sip_code=503"}' \
     http://localhost:8080/pcap/batch \
  -o busy-hour.zip
```
