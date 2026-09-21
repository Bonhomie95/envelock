# Envelock server architecture

~32k lines under `src/envelock`. This file records the layering rules the code
is converging on and the agreed order for the remaining splits, so future work
scales the structure instead of eroding it.

## Layers (import direction: top may import bottom, never the reverse)

```
main.py                  app wiring only (routers, middleware, lifespan)
api/                     routers — HTTP shape, auth deps, serialization. THIN.
services/                business logic shared by routers, workers, schedulers
workers/  notify/        background execution; must never import api/*
platform/ detections/    the detection brain (pure where possible)
channels/ billing/ llm/  integrations, each behind an injectable seam
security/ auth/ core/    primitives: crypto, limits, tokens, enums, events
models.py db.py config   foundations
```

Rules:

1. **Nothing imports `envelock.api.*` except `main.py`.** A helper needed
   outside its router moves to `services/` first (see `services/__init__.py`).
   Enforced by convention today; a lint guard is welcome.
2. **Routers do not hold business logic.** They validate, call a
   service/platform function, and shape the response.
3. **Deferred (function-body) imports are for lazy boot only** — never to dodge
   an import cycle. A cycle means something is in the wrong layer.
4. **Every integration keeps an injectable seam** (Transport, client_factory,
   verifier) so the suite runs with no network and no keys.

## Done so far

- `services/domains.py` — domain-control verification, shared by tenants
  router, channels router and the scheduler (previously: scheduler imported a
  router module; channels imported another router's private function).
- `security/webhook_auth.py` — push-callback HMACs, built by the channel layer
  and verified by the api layer (`api/_webhook_auth.py` is a shim).
- `auth/staff.new_temporary_password` — used by `security/bootstrap_staff`
  without touching a router.

## Next splits, in order of value

1. **`api/tenants.py` (≈2.5k lines, 39 routes)** → package
   `api/tenants/{tenants,domains,mailboxes,connect,alerts,counterparties,oversight}.py`
   with entitlement/capacity helpers (`_mailbox_entitled`, `_effective_plan`,
   `_mailbox_capacity`, `_seat_usage`…) lifted into `services/provisioning.py`.
2. **`api/channels.py` (≈1.1k lines)** → split out `sensor`, `push`,
   `oauth_connect`, `ingest` routers.
3. **`models.py` (29 models)** → `models/` package split by domain
   (`tenancy`, `mail`, `detection`, `billing`, `ops`) with a re-exporting
   `__init__` so `from envelock.models import X` keeps working everywhere.
4. **`security/limits.py` (4 concerns)** → `ratelimit`, `lockout`, `replay`,
   `revocation` modules.
5. **`detections/content.py`** → move the Group A detections it still holds
   next to the rest of Group A in `impersonation.py`; merge the arbitrary
   `identity.py`/`sessions.py` split.
6. **`platform/pipeline.build_context`** → batch the per-URL reputation and
   DNSBL lookups (they run sequentially in the per-message hot path).
7. **`workers/imap_fetch.sync_mailbox`** → an `ImapConnection` value object to
   collapse the 11-kwarg credential threading through `_enforce_copy`.
