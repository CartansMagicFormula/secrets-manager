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
| Stolen client token | Start token only logs in (audited, per instance, rate-limited); access tokens expire after 1 h (max 24 h) and live only in memory; revocation ends all sessions; Kubernetes: service-account identity instead of a file |
| Network sniffing / spoofing inside the platform | TLS 1.3 on the vault listener; clients trust only the fleet CA; services get short-lived certificates from CSRs |
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

- A client = name + **start token** (`smt_` + 43 chars, stored as HMAC-SHA256
  with a server key) + policies (path prefixes it may **read**) + certificate
  names (DNS names / IPs it may get certificates for).
- Clients never write, list or rotate. Admin only.
- Start token shown once at creation; revocable (ends all sessions at once).

### Start token → access token per container (decided 2026-10-08)

```
container start ── start token (file, long-lived, ONLY good for login) ──► POST /v1/auth/login {instance}
                ◄── access token sma_… (memory only, 1 h)
every call      ── access token ──► GET /v1/secrets/…, POST /v1/pki/issue
before expiry   ── POST /v1/auth/renew (+1 h, up to 24 h after login) ── then log in again
```

- Access tokens live only in the vault's memory (MAC) and the client's memory:
  a vault restart or seal ends every session; clients log in again by themselves.
- Each session is bound to one **instance** (hostname): the admin sees every
  running container, ends single sessions, and the audit log names the instance
  on every read. At most 20 sessions per client (the oldest is dropped).
- Honest limit: in Docker the start token is still a long-lived file (secret
  zero). The gain: the token that reads values is short-lived, per container,
  never on disk, and every login is audited. **Kubernetes (later):** the start
  token is replaced by the pod's projected service-account token (audience
  `secrets-manager`, minutes), verified by the vault; no long-lived file at all.

### One vault per environment, client lists, enrollment (decided 2026-10-08)

- **Three vaults** (dev, staging, production), each with its own master key,
  CA and secrets; `ENVIRONMENT` names it (shown in the UI, checked when a
  client list is applied). Paths carry no environment prefix.
- **Client lists** (`~/agents/coding/fleet/vault-clients/<env>.json`, no
  values): "Apply client list" (`POST /v1/admin/apply`) creates missing
  clients and generated secrets inside the vault and updates policies /
  certificate names. Never deletes, never returns values; reports static
  secrets still to be entered and clients not in the list.
- **Enrollment codes** deliver start tokens: the admin creates a one-time
  code (`sme_…`, 15 min, one open code per client, memory only, gone on
  seal); `POST /v1/auth/enroll` exchanges it once for a **new start token**
  (`sm-agent enroll` on the service server writes it to the token file, 0400).
  The vault runs on its own server, so the code is the only thing a person
  carries, and it is worthless after use or expiry.
- **Start-token rotation** = enrollment: the previous start token keeps
  working for the grace period (24 h), so running containers are not cut off.
  Clients created by a list have no usable start token until enrolled.

## Internal PKI (decided 2026-10-08)

- On init (or the first unseal of an older vault) the vault creates a root CA
  (ECDSA P-256, 10 years, path length 0). Its key lives only in the encrypted
  state; the public certificate is written to `CA_EXPORT_DIR/fleet-ca.crt`
  (shared Docker volume `fleet-ca`, mounted read-only by every client) and
  served at `GET /v1/pki/ca`.
- `POST /v1/pki/issue {csr, usage: server|client, ttl}`: the client sends a CSR,
  **its private key never reaches the vault**. Every DNS name / IP (server) or
  the common name (client, e.g. a DB user for mTLS) must be on the client's
  certificate names. Default 30 days, 1 h–90 days; ECDSA P-256/P-384 or RSA ≥ 2048.
  Issued certificates are listed (serial, names, expiry; no keys) and audited.
- **sm-agent** (second binary in the image) renews certificates after 2/3 of
  their lifetime and writes `tls.key` (0600) / `tls.crt` / `ca.crt`; optional
  reload signal to the service (shared PID namespace). It also writes secret
  values into files (tmpfs) for third-party images that cannot call the vault.
- The vault's own TLS listener uses a certificate from its CA, created in
  memory on unseal (7 days, renewed after half); while sealed a throwaway
  self-signed certificate that verifying clients reject. TLS 1.3 only.
- Not yet: revocation lists (certificates are short-lived instead), CA rotation
  (plan: new CA, both trusted during a transition), intermediate CA.

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
| `GET/POST/DELETE /v1/admin/clients` | admin | clients, policies, certificate names, start tokens (shown once) |
| `GET /v1/admin/sessions`, `DELETE /v1/admin/sessions/{id}` | admin | active client sessions per instance |
| `GET /v1/admin/certificates` | admin | CA certificate + issued certificates (no keys) |
| `GET /v1/admin/audit`, `GET /v1/admin/audit/verify` | admin | audit log |
| `POST /v1/admin/clients/{id}/enroll` | admin | one-time enrollment code (15 min) |
| `POST /v1/admin/apply` | admin | apply a client list (creates clients and generated secrets) |
| `POST /v1/auth/enroll` | enrollment code | new start token (once; previous token valid for the grace period) |
| `POST /v1/auth/login` | start token | access token for one instance |
| `POST /v1/auth/renew`, `POST /v1/auth/logout` | access token | extend / end the session |
| `GET /v1/secrets/{path}` | access token | current value (+ version); `?version=previous` during grace |
| `GET /v1/pki/ca` | anyone (unsealed) | CA certificate (public) |
| `POST /v1/pki/issue` | access token | certificate from a CSR for allowed names |

## Deployment

- Own compose project, one internal network per stack (`vault-osiris`,
  `vault-lumen`, `vault-gateway`), each joined only by that stack's clients,
  so stacks share no network with each other. Clients use TLS only
  (`https://secrets-manager:8443`). Admin UI: dev on a plain-HTTP listener bound
  to 127.0.0.1 that serves no client endpoints; production over TLS via a VPN /
  admin network. No internet egress at all.
- Read-only root, non-root (65532), no capabilities, data volume only.
- Backups: copy of `data/` (encrypted); restore drill; the master key is kept
  offline by the commander (paper / password manager), never in the repo or vault dirs.

## Not in scope (now)

Dynamic database credentials, HSM / cloud KMS auto-unseal, clustering, key
splitting (Shamir). Revisit when the fleet grows.
