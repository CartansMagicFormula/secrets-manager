# Secrets manager roadmap

## Inbox (ideas)

- 2026-10-08: Own vault instead of OpenBao (commander's decision): minimal attack
  surface, Go standard library only, UI included.

## Next

1. Commander initializes the real vault (UI), stores the master key offline
   (the running dev container still has the MVP image; redeploy first).
2. First clients: LLM gateway (provider keys), osiris-hub (Stripe, SMTP, analyzer token).
3. Services consume secrets and certificates (agreed 2026-10-08): Python client
   helper (osiris-hub, Lumen); sm-agent sidecars for Postgres, Valkey, SeaweedFS,
   Keycloak; **TLS on every connection to databases, caches and storage, also on
   private networks**.
4. Audit head hash shipped daily to Siren (outside verification of the chain).

## Later

- Kubernetes login: projected service-account tokens (audience `secrets-manager`)
  verified by the vault, instead of start-token files.
- mTLS between services with client certificates from the CA (DB users by
  certificate, no passwords).
- CA rotation (two CAs trusted during a transition); optional intermediate CA.
- Key splitting for the master key (e.g. 2 of 3) — only with a reviewed
  implementation; until then the master key is held by the commander.
- External security review of the crypto usage.
- Automatic rotation schedules for generated secrets; notify clients (webhook / NATS).
- Backup / restore drill documented and tested.

## Done

- 2026-10-08: One vault per environment (`ENVIRONMENT`), client lists applied
  in the UI (generated secrets created inside the vault), one-time enrollment
  codes, start-token rotation with grace period, `sm-agent enroll`.

- 2026-10-08: Start token → short-lived access token per container instance
  (renewal, max lifetime, sessions in the UI, per-instance audit); internal PKI
  (CA, certificates from CSRs with name allow lists, inventory); vault listener
  TLS 1.3 with its own CA certificate; sm-agent; Go client; end-to-end test
  with the LLM gateway (23 checks).

- 2026-10-08: MVP — encrypted state, seal / unseal, admin UI, static and generated
  secrets with versions and grace period, clients with read policies, audit chain,
  master key rotation; scratch image 11 MB; unit tests and live test against a
  throwaway container.
