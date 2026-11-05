# Nestack Secure Records API

Multi-tenant records API for the Nestack cybersecurity assessment. Python,
FastAPI, SQLite, and standard-library cryptography. There is no auth framework:
password hashing, sessions, access control, and lockout are implemented in this
repository.

## Routes

| Method | Endpoint | Auth | Body | Success |
| --- | --- | --- | --- | --- |
| POST | `/register` | no | `{username, password}` | `201` with the new user (`role` is always `user`) |
| POST | `/login` | no | `{username, password}` | `200` with a bearer token; `401` bad credentials; `429` locked |
| POST | `/records` | bearer | `{title, body}` | `201` with the record |
| GET | `/records/:id` | bearer | — | `200` if owner or admin; `404` otherwise |
| POST | `/logout` | bearer | — | `204`, revokes the current token |
| GET | `/healthz` | no | — | `200` when the database is reachable |

`/logout` and `/healthz` are operational additions; they are not required by the
brief. `/docs` is available while `NESTACK_ENABLE_DOCS=true`.

## Run it

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export NESTACK_DB_PATH=./nestack.db
uvicorn app.asgi:app --host 127.0.0.1 --port 8000 --no-server-header
```

The API is at `http://127.0.0.1:8000`. The database and schema are created on
first start. `NESTACK_ENABLE_DOCS=false` removes `/docs` and `/openapi.json`.

Create an admin (registration can never do this):

```bash
NESTACK_DB_PATH=./nestack.db python scripts/promote_admin.py alice
```

### Walkthrough

```bash
# Register two users
curl -sS -X POST localhost:8000/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct horse battery staple"}'

curl -sS -X POST localhost:8000/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"correct horse battery staple"}'

# Log in and keep the token
TOKEN=$(curl -sS -X POST localhost:8000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct horse battery staple"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# Create a record
curl -sS -X POST localhost:8000/records \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Private note","body":"only alice can read this"}'
```

As user `bob`, `GET /records/1` returns `404`. After `promote_admin.py bob`,
the same request returns the record.

## Configuration

All configuration is environment-based. Nothing secret is committed; the
repository only contains `.env.example`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NESTACK_DB_PATH` | `nestack.db` | SQLite file path |
| `NESTACK_SESSION_TTL` | `28800` | Session lifetime in seconds (8 hours) |
| `NESTACK_LOCKOUT_THRESHOLD` | `5` | Failed logins before the account locks |
| `NESTACK_LOCKOUT_SECONDS` | `900` | Lock duration in seconds |
| `NESTACK_MAX_BODY_BYTES` | `65536` | Whole-request body limit |
| `NESTACK_SCRYPT_N` | `32768` | scrypt CPU/memory cost (`2^15`) |
| `NESTACK_SCRYPT_R` | `8` | scrypt block size |
| `NESTACK_SCRYPT_P` | `1` | scrypt parallelisation |
| `NESTACK_PASSWORD_PEPPER` | unset | Optional secret mixed into every password |
| `NESTACK_ENABLE_DOCS` | `true` | Expose `/docs` and `/openapi.json` |
| `NESTACK_LOG_LEVEL` | `INFO` | Application log level |

`Settings` validates the values at startup. A pepper, if used, must be at least
16 characters and must never change after accounts exist.

## Design

### Password storage

- **scrypt** from `hashlib`, not plaintext and not a fast hash. Each password
  gets a fresh 128-bit salt from `secrets.token_bytes`. The stored format is
  `scrypt$N$r$p$salt$hash`, so parameters can be raised later without changing
  the schema.
- Verification uses `hmac.compare_digest`. Unknown usernames are verified
  against a dummy hash so a missing account costs the same as a real one.
- Password policy is length-based (10–128 characters), not composition rules,
  following NIST SP 800-63B. The upper bound prevents an attacker from turning
  login into a very expensive scrypt call.
- The optional pepper is an HMAC-SHA256 pre-hash keyed by a value stored outside
  the database. If only a database backup leaks, the attacker still needs the
  application secret before guessing.
- Default cost is `N=2^15` (32 MiB, about 90 ms per hash on the test machine).
  This is a deliberate trade-off: `N=2^17` is stronger (about 0.7 s and 128 MiB
  here) but makes concurrent unauthenticated logins a memory-exhaustion lever.
  Raise `NESTACK_SCRYPT_N` if the deployment can absorb it.

### Sessions

- On login the server generates 32 random bytes with `secrets.token_urlsafe`.
  The token is returned once in the response body; only its SHA-256 digest is
  stored in `sessions`. A stolen database therefore does not yield usable
  tokens.
- Clients send `Authorization: Bearer <token>`. The header is checked on every
  request, and the session row must exist and not be expired. There is no
  unsigned or "decode locally" path.
- Tokens are opaque rather than JWT because revocation is immediate and there is
  no signing key to manage. Login creates a new session; logout deletes it.
  Expired sessions are purged on successful login.
- Bearer headers (not cookies) mean there is no ambient credential and therefore
  no CSRF surface. There is intentionally no CORS configuration and no browser
  frontend.

### Object-level access control

`GET /records/:id` fetches the record and then checks
`record.owner_id == user.id or user.role == "admin"`. A failed check returns
`404`, the same response as a missing record, so a user cannot probe for the
existence of someone else's ids.

The owner of a new record always comes from the authenticated session.
`owner_id` is not an accepted request field, and unknown fields are rejected.
There is no list endpoint, so there is no second path where ownership filtering
could be forgotten. The rule is enforced in one place (`routes_records.py`) and
covered by cross-tenant tests.

### Roles

- `users.role` has a database `CHECK` constraint (`user` or `admin`).
- `POST /register` inserts the literal `'user'`. If the JSON body contains a
  `role` key at all, the request is rejected with `403`, even if the value is
  `"user"` or `null`.
- There is no profile-update endpoint, so a user cannot edit their own role.
- Admin is granted only by `scripts/promote_admin.py`, which requires direct
  database access. No HTTP route writes the role column.

### Input validation and SQL

- Pydantic models reject missing fields, wrong types, unknown fields, empty
  strings, NUL characters, and over-length values with `400`.
- Limits: username 3–32 characters (`[A-Za-z0-9._-]`, alphanumeric ends),
  password 10–128, title 1–200, body 1–16,384.
- A pure-ASGI middleware caps the whole request body at 64 KiB and returns
  `400 payload_too_large`, including when `Content-Length` is absent. This is
  checked before parsing, so oversized bodies never reach the application.
- Every SQL statement uses `?` placeholders. There is no string-built SQL
  anywhere; record ids are typed as integers by FastAPI before reaching SQLite.
- SQLite runs with `foreign_keys=ON`, `busy_timeout=5000`, and WAL mode.

### Login abuse resistance

- Failures are counted per account in `users.failed_attempts`, not per IP.
- The increment and lock decision are one atomic `UPDATE ... RETURNING`, so
  parallel guesses cannot lose attempts.
- The first four failures return `401`. The fifth sets `locked_until` and
  returns `429` with `Retry-After`. While locked, even the correct password
  returns `429`; after expiry the counter resets and the user gets a fresh set
  of attempts.
- A successful login clears the counter and `locked_until`.
- Usernames are case-insensitive (`COLLATE NOCASE`), so `Alice` and `alice`
  cannot be attacked as separate accounts.

### Errors and logging

All errors use the same envelope:

```json
{"error": {"code": "invalid_input", "message": "Request validation failed.", "details": [{"field": "title", "message": "..."}]}}
```

Stack traces, SQL, and internal exception text never reach the client. A request
id is accepted (if well-formed) or generated, returned in `X-Request-ID`, and
included in logs. Passwords, raw tokens, and `Authorization` headers are never
logged.

## Threat model

### Assets

1. Record contents (the sensitive data).
2. Password verifiers and the accounts they protect.
3. Session tokens.
4. The admin role and its read-any capability.

### Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Offline password cracking after a DB leak | scrypt with per-user salts and optional pepper | Weak passwords can still be guessed; cost is the defence |
| Session theft from a DB leak | Only SHA-256 digests of 256-bit tokens are stored | A live token stolen from a client is usable until expiry |
| Session forgery | Opaque random token checked against the DB on every request | None practical at 256 bits |
| IDOR / cross-tenant read | Owner check on every read; `404` for not-owned; owner from session | A bug in that one check would be high impact, hence tests |
| Privilege escalation | Role literal on insert; `role` field rejected; no profile update; DB `CHECK`; CLI-only promotion | Someone with DB or shell access can promote themselves by design |
| SQL injection | Parameterised queries everywhere; integer path parameter | None in the current routes |
| Brute force | Per-account lockout, dummy hash for unknown users, 429 + `Retry-After` | An attacker can lock a known account (DoS); see limitations |
| Credential stuffing | Same lockout, plus short password max to bound work | No MFA, no breached-password check |
| Oversized / malformed input | Pydantic limits plus 64 KiB ASGI body cap; 400 responses | Memory use is bounded per request, not globally |
| User enumeration | Generic `401` for bad credentials | Registration `409` and lockout `429` reveal that a username exists |
| Log leakage | No passwords, tokens, or auth headers logged; request ids only | Downstream log aggregation must be protected |
| CSRF | Bearer token in a header, no cookies, no CORS | Reintroducing cookies would require CSRF defences |
| Clickjacking / MIME sniffing | `X-Frame-Options: DENY`, `nosniff`, CSP on API routes | Browser-only concern for JSON |
| Transport interception | TLS terminated by the proxy; HSTS emitted on HTTPS requests | Deployment must actually enable TLS |

### If the user table leaked

An attacker with a dump of `users` gets usernames, roles, scrypt parameters,
per-user salts, password hashes, failure counters, and timestamps. They do **not**
get plaintext passwords, reusable session tokens, or the pepper (if configured).
They can:

- identify which account is the admin;
- run an offline guessing attack against each hash, with the cost of scrypt and
  a unique salt per user. Identical passwords do not produce identical hashes,
  so one crack does not reveal other users with the same password.

If the whole database leaked rather than just `users`, records and their bodies
are also exposed. Record contents are not encrypted at rest in this version;
that is listed under limitations rather than hidden.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite has 56 tests. It uses a temporary SQLite database and reduced scrypt
cost (`N=2^14`) so it stays fast; production defaults remain higher.

| File | What it proves |
| --- | --- |
| `tests/test_auth.py` | Registration always creates `user`; `role` is rejected with 403; passwords and session tokens are not stored in plaintext; duplicate usernames are case-insensitive |
| `tests/test_sessions.py` | Missing, malformed, invalid, expired, and revoked tokens are rejected; record ownership comes from the session |
| `tests/test_records.py` | Owner read, cross-tenant `404` with no data leak, admin read, missing record, body spoofing, SQL injection in the path |
| `tests/test_lockout.py` | Fifth failure returns 429; correct password is refused while locked; expiry and success reset counters; lockout is per account and case-insensitive |
| `tests/test_validation.py` | Missing/wrong-typed/oversized/blank/NUL input returns 400; malformed JSON and oversized HTTP bodies return 400; errors do not leak internals |
| `tests/test_security.py` | Security headers, request ids, JSON 404/405, docs toggle, generic 500 |
| `tests/test_passwords.py` | Hash/verify round trip, unique salts, pepper, tampered and malformed hashes, token format |

## Layout

```
app/
  asgi.py            uvicorn entry point
  main.py            app factory, body limit, headers, request id, health
  config.py          environment settings
  db.py              SQLite connections, schema, transactions
  security.py        scrypt hashing and opaque tokens
  repositories.py    every SQL query
  auth.py            register / login / lockout / session checks
  deps.py            database and bearer-token dependencies
  schemas.py         request and response models
  routes_auth.py     /register /login /logout
  routes_records.py  /records
  errors.py          uniform JSON errors
scripts/
  promote_admin.py   the only way to create an admin
tests/
```

## Deployment notes

- Run behind a TLS-terminating reverse proxy and forward only the headers you
  trust (`--proxy-headers` with a fixed set of proxy IPs). HSTS is emitted when
  the request scheme is `https`.
- Set `NESTACK_ENABLE_DOCS=false` in production.
- Set a long random `NESTACK_PASSWORD_PEPPER` and keep it in the platform secret
  store, not in the repo. Never rotate it without a password migration.
- Restrict the database file to the service user (`0600`) and encrypt backups.
- The included Dockerfile runs as a non-root user and stores the database under
  `/data`.
- Start uvicorn with `--no-server-header`.
- Alert on spikes in `login_locked` and `admin_record_read` log events.

## Limitations and next steps

- **Single node.** Sessions and lockout live in SQLite. A multi-instance
  deployment needs Postgres/Redis and the same atomic update semantics.
- **Lockout is a denial-of-service lever.** An attacker who knows a username can
  lock it with five requests. The brief requires lockout; a production system
  would add exponential backoff, notifications, and a per-IP volumetric limit at
  the edge rather than a hard lock.
- **Username enumeration.** Registration returns `409` and a locked account
  returns `429`, which reveals existence. Credential responses themselves are
  uniform. Email verification and uniform registration responses would reduce
  this.
- **No MFA, password reset, or breached-password checks.**
- **Records are not encrypted at rest.** Application-level envelope encryption
  with a KMS-held key would limit the impact of a full database leak.
- **No refresh tokens or idle timeout.** Sessions have an absolute 8-hour TTL.
- **Audit logs go to stdout.** Ship them to append-only storage if they are part
  of the compliance story.
- **No per-IP rate limiting.** It is intentionally absent from the account
  lockout path (the brief asks for per-account tracking); put volumetric limits
  in the proxy/WAF.
