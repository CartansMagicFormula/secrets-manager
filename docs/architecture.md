# Secrets manager — architecture

Our own thin vault (decided 2026-10-08 instead of OpenBao). One static Go
binary, **standard library only**, image `FROM scratch`. It stores the fleet's
high-value secrets (LLM provider keys, Stripe, SMTP, publisher tokens, service
tokens), hands each client only what its policy allows, rotates generated
secrets, and keeps a tamper-evident audit log. It has a small admin UI
(vanilla HTML/JS, embedded; no npm, no framework).

We write **no cryptographic primitives**: AES-256-GCM, SHA-256, HMAC, PBKDF2,
`crypto/rand`, TLS and X.509 come from Go's standard library. Our risk is in
*using* them; the rules below and the tests target exactly that.

## Threat model (short)

| Threat | Mitigation |
|---|---|
| Disk / backup / volume stolen | Everything at rest is encrypted; the master key is never stored by the service |
| Data file modified or swapped | AES-GCM authentication + associated data binds the state to its format and generation |
| Compromised client service | Policies: a client reads only its own paths, never writes, never lists other paths; tokens revocable; every read audited |
| Stolen client token | Token valid only on the internal network; revocation; rotation; later mTLS (no bearer token) |
| Admin UI attack (XSS / CSRF / brute force) | Strict CSP (no inline script), SameSite=Strict session cookie, CSRF header, login rate limit + backoff, PBKDF2 (600k) password hash |
| Supply-chain attack on dependencies | No third-party modules; scratch image; Go toolchain image pinned by digest |
| Log leaks | Values never logged, never in errors, never in list responses; reveal only explicit and audited |
| Insider / agent reading secrets | Values only via the authenticated API; Claude never handles values (agent rules); unseal key held by the commander only |

## Keys and data at rest

```
master key (32 random bytes, held by the commander, entered to unseal)
   └─ wraps ─ state key (32 random bytes, AES-256-GCM)
                 └─ encrypts ─ state (JSON: secrets + versions, clients, admin, settings)
```

- State file `data/state.json` = header (format, generation, wrapped state key,
  nonce) + ciphertext. Each save: new random 96-bit nonce, generation + 1,
  associated data = `secrets-manager/v1|<generation>`; written atomically
  (temp file, fsync, rename).
- Changing the master key re-wraps the state key only.
- Sealed = no keys in memory; every API except status / init / unseal is refused.
- Optional dev auto-unseal from a key file (Docker secret) — **weaker** (key on
  the same host), off by default, documented as dev only.

## Clients and policies

- A client = name + token (`smt_` + 43 chars, stored as HMAC-SHA256 with a
  server key) + policies: list of path prefixes it may **read**.
- Clients never write, list or rotate. Admin only.
- Token shown once at creation; revocable; last use recorded.
- Phase 2: mTLS client certificates from the vault's own CA (no bearer tokens).

## Secrets

- Path `service/name` (lowercase, `[a-z0-9_-]`, 2–5 segments).
- Versions: every change is a new version; the current version is served; the
  previous one stays readable for a grace period (rotation of shared tokens).
- Kinds: `static` (value set by the commander) and `generated` (random value
  created by the vault; `rotate` creates a new version). Generated lengths /
  alphabets per secret.

## Admin

- Created at init (username + password, PBKDF2-HMAC-SHA256, 600 000 iterations).
- Session cookie (random 32 bytes, HttpOnly, SameSite=Strict, Secure), 30 min idle.
- State-changing requests need header `X-Requested-With: secrets-manager`.
- Login: 5 attempts / minute per IP, then exponential backoff.

## Audit

- `data/audit.log`: JSON lines `{time, actor, action, path, version, ok, prev, hash}`,
  `hash = SHA-256(prev || canonical entry)` → tamper-evident chain; never values.
- `GET /v1/admin/audit/verify` recomputes the chain. Later: head hash shipped to
  Siren daily, so a rewritten chain is detectable from outside.

## API (JSON)

| Endpoint | Who | Purpose |
|---|---|---|
| `GET /health`, `GET /v1/sys/status` | anyone | liveness; initialized / sealed |
| `POST /v1/sys/init` | anyone, once | create state, admin; returns the master key **once** |
| `POST /v1/sys/unseal`, `POST /v1/sys/seal` | anyone / admin | load / drop keys |
| `POST /v1/admin/login`, `POST /v1/admin/logout` | admin | session |
| `GET /v1/admin/secrets` | admin | metadata only (no values) |
| `PUT /v1/admin/secrets/{path}` | admin | set a static value or create a generated secret |
| `POST /v1/admin/secrets/{path}/reveal` | admin | value (audited) |
| `POST /v1/admin/secrets/{path}/rotate` | admin | new version of a generated secret |
| `DELETE /v1/admin/secrets/{path}` | admin | delete (all versions) |
| `GET/POST/DELETE /v1/admin/clients` | admin | clients, policies, tokens (shown once) |
| `GET /v1/admin/audit`, `GET /v1/admin/audit/verify` | admin | audit log |
| `GET /v1/secrets/{path}` | client token | current value (+ version); `?version=previous` during grace |

## Deployment

- Own compose project, internal network `secrets` joined only by its clients
  (LLM gateway, osiris-hub, publisher, …); admin UI on 127.0.0.1 in dev, via a
  VPN / admin network in production. No internet egress at all.
- Read-only root, non-root (65532), no capabilities, data volume only.
- Backups: copy of `data/` (encrypted); restore drill; the master key is kept
  offline by the commander (paper / password manager), never in the repo or vault dirs.

## Not in scope (now)

Dynamic database credentials, HSM / cloud KMS auto-unseal, clustering, key
splitting (Shamir). Revisit when the fleet grows.
