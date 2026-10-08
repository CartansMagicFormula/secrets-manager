# Secrets manager roadmap

## Inbox (ideas)

- 2026-10-08: Own vault instead of OpenBao (commander's decision): minimal attack
  surface, Go standard library only, UI included.

## Next

1. Commander initializes the real vault (UI), stores the master key offline.
2. First clients: LLM gateway (provider keys), osiris-hub (Stripe, SMTP, analyzer token).
3. Small client helpers: Python (osiris-hub, Lumen) and Go (LLM gateway, publisher);
   fetch at start, re-read on rotation, never log values.
4. Audit head hash shipped daily to Siren (outside verification of the chain).

## Later

- mTLS client certificates from the vault's own CA (no bearer tokens).
- Key splitting for the master key (e.g. 2 of 3) — only with a reviewed
  implementation; until then the master key is held by the commander.
- External security review of the crypto usage.
- Automatic rotation schedules for generated secrets; notify clients (webhook / NATS).
- Backup / restore drill documented and tested.

## Done

- 2026-10-08: MVP — encrypted state, seal / unseal, admin UI, static and generated
  secrets with versions and grace period, clients with read policies, audit chain,
  master key rotation; scratch image 11 MB; unit tests and live test against a
  throwaway container.
