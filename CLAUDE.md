# Secrets manager — Project Guide

The fleet's own thin vault: one Go binary, **standard library only, zero
third-party modules**, image `FROM scratch`. Stores high-value secrets, serves
each client only its policy paths (read-only), rotates generated secrets, runs
the fleet's internal CA (short-lived TLS certificates from CSRs), keeps a
hash-chained audit log, has an embedded admin UI (plain HTML/CSS/JS, no npm).
Architecture and threat model: `docs/architecture.md`; connecting services:
`docs/clients.md`; roadmap: `docs/roadmap.md`.

Fleet-wide rules apply and have priority: `~/agents/coding/framework/rules/agent-rules.md`.

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
# unseal after every restart, create secrets and clients (start tokens shown once).
```

One vault per environment (`ENVIRONMENT`: dev / staging / production; staging
and production on their own servers). Normal setup is scripted:
`~/agents/coding/framework/scripts/fleet.sh up` (runbook: `~/agents/coding/fleet/runbook.md`)
initializes / unseals, applies the client list
(`~/agents/coding/fleet/config/vault-clients/<env>.json`) and enrolls every client,
using the admin commands inside the container (loopback; secrets on stdin):

```bash
docker compose -p secrets-manager -f docker/docker-compose.yml exec -T secrets-manager \
  /secrets-manager admin status|init -user U|unseal|apply -user U|enroll -user U CLIENT...
```

Clients join their stack's internal network to the vault (`vault-osiris`,
`vault-lumen`, `vault-gateway`: stacks share no network), mount the volume
`fleet-ca` read-only and talk TLS only: `POST https://secrets-manager:8443/v1/auth/login`
with the start token → access token → `GET /v1/secrets/<path>`, `POST /v1/pki/issue`.
Third-party images get `sm-agent` copied into the image (writes into the
container's tmpfs; `-exec` for images without a shell). Details: `docs/clients.md`.

## Tests

```bash
docker run --rm -v "$PWD":/src -w /src -e GOCACHE=/tmp/gocache --user $(id -u):$(id -g) \
  golang:1.27.1-alpine3.24 sh -c "gofmt -l . ; go vet ./... && go test ./..."
```

Covered: crypto (wrong key, tampering, nonce freshness, password hashing,
uniform random strings), PKI (name allow list, weak keys, tampered CSRs, usage
separation, TLS handshake against the CA), store (no plaintext on disk, header
tampering, master key rotation, versions, policies on segment boundaries),
audit (edited / removed entries detected), server (full flow, seal / unseal,
CSRF, forged and expired sessions, brute-force limits, start vs. access tokens,
renewal limits, session cap, admin-only listener), client and sm-agent against
a real TLS vault (re-login after unseal, foreign CA rejected, renewal, rotation).
End-to-end with the LLM gateway: `~/agents/llm-gateway/test/e2e/run.sh`.

## Structure

```
cmd/secrets-manager/   main: TLS listener, optional dev admin HTTP listener, auto-unseal (dev), healthcheck
cmd/sm-agent/          sidecar / init container: certificates + secret files for third-party services
internal/crypto/       AES-256-GCM seal/open with associated data, PBKDF2, HMAC, random strings
internal/pki/          internal CA: create, issue from CSRs (allow list), vault server certificate
internal/store/        encrypted state file (state key wrapped by master key), atomic writes
internal/audit/        hash-chained JSON-lines log, verify
internal/server/       HTTP API, admin sessions, client login / access tokens, enrollment codes,
                       client lists, PKI endpoints, rate limits
internal/client/       Go client (used by sm-agent; template for Go services)
internal/testvault/    throwaway TLS vault for tests
web/                   admin UI (embedded)
docker/                Dockerfile (scratch, both binaries), compose (networks vault-<stack>, volume fleet-ca)
```
