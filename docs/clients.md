# Connecting a service to the secrets manager

Two ways, depending on whether we control the service's code.

## 1. Our own services (Go, Python): direct client

The service reads its values from the vault at start, keeps them in memory and
re-reads them periodically / on SIGHUP (rotation). Nothing is written to disk.

| Setting | Value |
|---|---|
| `VAULT_URL` | `https://secrets-manager:8443` (the stack's network `vault-<stack>`) |
| `VAULT_CA_FILE` | `/ca/fleet-ca.crt` (volume `fleet-ca`, read-only) |
| `VAULT_TOKEN_FILE` | start token: `/run/vault-token/token` (external volume `vault-token-<client>`, read-only) |
| `VAULT_INSTANCE` | optional, default hostname |

Rules for the client code (Go: copy of `internal/client`, as in the LLM gateway;
Python: same flow with the standard library `ssl` + `http.client`):

- TLS 1.3, trust only the fleet CA, never disable verification.
- Login → access token in memory; renew 5 min before expiry; on 401 log in
  again once (vault restarted); after 24 h a fresh login.
- Temporary outage (sealed 503, unreachable): keep the last known values and
  retry. Refusal (403, revoked): drop the value.
- Never log values or tokens; errors name the path, never the value.

## 2. Third-party images (Postgres, Valkey, SeaweedFS, Keycloak): sm-agent

`sm-agent` writes certificates and secret values into files the service reads.
It is **copied into the service's own image** (we build thin images on top of
the official ones anyway), so the files land in the container's private tmpfs:
no shared volume, no second container. (Docker tmpfs volumes shared with an
init container would be emptied as soon as the init container exits.)

```dockerfile
ARG SM_IMAGE=secrets-manager:latest
FROM ${SM_IMAGE} AS sm
FROM pgvector/pgvector:pg17
COPY --from=sm /sm-agent /usr/local/bin/sm-agent
```

Entrypoint script (images with a shell), as in osiris `docker/postgres`:

```sh
/usr/local/bin/sm-agent -once ${SM_ARGS}          # values + certificate, waits while sealed
/usr/local/bin/sm-agent ${SM_RENEW_ARGS} -reload-pid 1 -reload-signal HUP &   # renewer
exec /usr/local/bin/docker-entrypoint.sh "$@"
```

```yaml
    environment:
      SM_URL: https://secrets-manager:8443
      SM_CA_FILE: /ca/fleet-ca.crt
      SM_TOKEN_FILE: /run/vault-token/token
      SM_ARGS: >-
        -cert osiris-postgres -cert-dir /var/lib/postgresql/certs
        -secret osiris/postgres/superuser-password=postgres_superuser_password -secret-dir /run/vault
    tmpfs:
      - /run/vault:mode=0700,size=1m,uid=999,gid=999,noexec,nosuid,nodev
    volumes: [fleet-ca:/ca:ro, vault-token-osiris-postgres:/run/vault-token:ro]
    networks: [backend, vault-osiris]
```

Images without a shell (scratch): `-exec` mode, sm-agent fetches once and then
replaces itself with the service (same PID 1):

```dockerfile
ENTRYPOINT ["/usr/local/bin/sm-agent", "-once", "-secret", "osiris/analyzer/token=analyzer_token",
            "-secret-dir", "/run/vault", "--", "/usr/local/bin/osiris-analyzer"]
```

- Certificates: new key + CSR on every renewal (after 2/3 of the lifetime,
  default 30 days); files `tls.key` (0600), `tls.crt` (chain), `ca.crt`.
- Secrets: `-secret path=file -secret-dir /run/sm` (mount a tmpfs there), files 0400.
- `-once` for an init container (waits while the vault is sealed).
- Reload: Postgres reloads certificates on SIGHUP; services without a reload
  signal re-read files themselves (our Go services) or need a restart (noted
  per service).

## Vault side: client list and enrollment (scripted)

One client per service and purpose (least privilege), defined in the
environment's client list (`~/agents/coding/fleet/config/vault-clients/<env>.json`).
`fleet.sh up` does all of it (runbook: `~/agents/coding/fleet/runbook.md`):

1. **Apply** (`secrets-manager admin apply`, also a UI button): creates clients
   and generated secrets; lists static secrets to enter in the Secrets tab.
2. **Enroll** (`secrets-manager admin enroll CLIENT...`): one-time code per
   client (15 min, single use), exchanged right away by
   `sm-agent enroll -out /tokens/token -owner <uid:gid>` (as root with only
   CAP_CHOWN) into the volume `vault-token-<client>`: file 0400, owned by the
   service's user. Skipped when the volume exists.
3. Rotating a start token = `fleet.sh enroll --force <client>`; the old token
   keeps working for 24 h.

The admin commands run inside the vault container over its loopback
(`docker exec`), so the master key and admin password never cross a network;
they are read from stdin, never from arguments.
