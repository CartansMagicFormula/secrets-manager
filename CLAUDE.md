# Secrets manager — Project Guide

The fleet's own thin vault: one Go binary, **standard library only, zero
third-party modules**, image `FROM scratch` (~11 MB). Stores high-value
secrets, serves each client only its policy paths (read-only), rotates
generated secrets, keeps a hash-chained audit log, has an embedded admin UI
(plain HTML/CSS/JS, no npm). Architecture and threat model:
`docs/architecture.md`; roadmap: `docs/roadmap.md`.

Fleet-wide rules apply and have priority: `~/agents/coding/docs/agentic-ai/agent-rules.md`.

- **Claude never handles real secret values**: the real vault is initialized and
  unsealed by the commander in the UI; the master key exists only with the
  commander. Agents work with throwaway test instances only.
- **Never add a dependency.** Only the Go standard library (`go list -m all` must
  print only `secrets-manager`). No cryptographic primitives of our own.
- Work happens on branch `development`.

## Running

```bash
docker compose -p secrets-manager -f docker/docker-compose.yml up -d --build
# Admin UI (dev): http://localhost:8200 → initialize once (store the master key offline),
# unseal after every restart, create secrets and clients (tokens shown once).
```

Clients join the external internal network `fleet-secrets` and read
`GET http://secrets-manager:8200/v1/secrets/<path>` with `Authorization: Bearer smt_…`.

## Tests

```bash
docker run --rm -v "$PWD":/src -w /src -e GOCACHE=/tmp/gocache --user $(id -u):$(id -g) \
  golang:1.27.1-alpine3.24 sh -c "gofmt -l . ; go vet ./... && go test ./..."
```

Covered: crypto (wrong key, tampering, nonce freshness, password hashing,
uniform random strings), store (no plaintext on disk, header tampering, master
key rotation, versions, policies on segment boundaries), audit (edited /
removed entries detected), server (full flow, seal / unseal, CSRF, forged and
expired sessions, brute-force limit, validation, grace period, headers).

## Structure

```
cmd/secrets-manager/   main: config from env, optional dev auto-unseal, healthcheck subcommand
internal/crypto/       AES-256-GCM seal/open with associated data, PBKDF2, HMAC, random strings
internal/store/        encrypted state file (state key wrapped by master key), atomic writes
internal/audit/        hash-chained JSON-lines log, verify
internal/server/       HTTP API, admin sessions, clients, policies, rotation, rate limits
web/                   admin UI (embedded)
docker/                Dockerfile (scratch), compose (network fleet-secrets)
```
