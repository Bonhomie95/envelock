# Envelock

Email fraud and account-takeover protection for B2B and P2P businesses.

**We stop your money going to the wrong bank account.**

| | |
|---|---|
| **Launch guide** | [`server/docs/LAUNCH-GUIDE.md`](server/docs/LAUNCH-GUIDE.md) — building the server, every key, and everything left to do |
| **Backend** | [`server/`](server/) — Python, FastAPI, SQLAlchemy · layering rules in [`server/docs/ARCHITECTURE.md`](server/docs/ARCHITECTURE.md) |
| **Frontend** | [`client/`](client/) — React, Vite, Tailwind, TypeScript |
| **Admin console** | [`admin/`](admin/) — the operator console, port 5174 |

---

## Run it

Two terminals. Requires **PostgreSQL** (the only supported database) and, for
multi-instance deployments, Redis.

**API** (port 8010):

```bash
cd server
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env          # then generate the two secrets it names

# Create the role + database once (any Postgres works):
#   createuser envelock --createdb && createdb -O envelock envelock
ENVELOCK_POSTGRES_DSN="postgresql+asyncpg://envelock:envelock@localhost:5432/envelock" \
  python -m uvicorn envelock.main:app --reload --app-dir src --port 8010
```

The schema is created automatically on first start. Going to production is a
single change: point `ENVELOCK_POSTGRES_DSN` at your server's database.

**Web** (port 5173):

```bash
cd client && npm install && npm run dev
```

Open <http://localhost:5173>.

> If it reports `Port 5173 is already in use`, an older dev server is still
> running — `pkill -f vite`, then start again. The port is pinned deliberately:
> Vite's default is to move quietly to 5174, which leaves you looking at a stale
> server on 5173 and wondering why the styling is gone.

For managed migrations and row-level security in production, run
`alembic upgrade head` in `server/` instead of relying on auto-create.

**Production:** one repository, one server. `server/deploy/setup-server.sh`
builds a fresh Ubuntu 24.04 VPS end to end; `~/deploy/deploy.sh` ships every
change after that. Step by step: [`server/docs/LAUNCH-GUIDE.md`](server/docs/LAUNCH-GUIDE.md).
CI runs per app from `.github/workflows/` (server, client, admin).

Tests: `cd server && pytest` — 785 tests · Lint: `ruff check src tests` ·
Build: `cd client && npm run build` (also builds the sensor packages) ·
Sensor tests: `cd client && npm run test:sensor` — 54 tests

---

## What to try

| Page | What it does |
|---|---|
| **/** | Landing. Pricing, the AI-analyst section with a sample verdict, the shared-network counts, and the **live** domain scanner — it runs the real lookalike engine with no account and no mailbox access. |
| **/analyse** | Detection sandbox. Paste any raw email; the production detection suite runs on it. |
| **/signin** | Real signup → mandatory TOTP two-factor → session. |
| **/dashboard** | Live alert queue, money stopped, mailbox coverage, connection advisor, attack simulation. |
| **/status** | Public status page, read live from the running system. |
| **/terms** · **/privacy** · **/dpa** · **/subprocessors** | Legal. The DPA says on its face that it is a drafting aid pending counsel. |

Worth checking specifically:

- **Sign up, connect a mailbox, then post three ordinary invoices to `/api/v1/ingest`.** The vendor and their bank account are learned. Post a fourth changing the account and it fires **Critical** with the callback number *on file with you* — not the one in the email.
- **Dashboard → RUN SIMULATION** sends four benign look-alike attacks through the real engine. Expect **4/4 detected**. Simulations are analysed but never stored as alerts.
- **Mailbox coverage** shows each mailbox's protection level *derived from what its connection can actually do*, and names the detections that are inactive. An IMAP mailbox cannot read server-side rules, so C1/C2/C4 are listed as inactive rather than quietly skipped.
- **Quarantine a forwarding-connected mailbox's alert** — it refuses, and says why. The copy arrives post-delivery, so nothing can be removed.
- **Connection advisor** reads real MX records. Try `hinet.net` or your own domain.

---

## Architecture

Three independent channels feed one normalised event stream:

- **Mail** — Graph/Gmail APIs, admin APIs, direct IMAP, or a forwarded copy
- **Identity** — provider sign-in logs, or the client sensor on the device
- **External** — Certificate Transparency, zone files, RDAP, DMARC reports

Each channel has a fallback that works everywhere: every mail system supports
forwarding, the sensor runs on the device rather than the server, and the
external channel needs no mailbox access at all. That is what makes coverage
universal while fidelity stays honestly disclosed per mailbox.

Three rules keep it coherent, all enforced in code:

1. **Detections never branch on `source`.** Everything normalises into `core/events.py`, so detection logic is written once.
2. **Coverage is derived, never declared.** `core/capabilities.py` computes each mailbox's protection level and names its inactive detections.
3. **The registry loads deterministically.** `detections/__init__.py` imports every module, so the active detection set can never depend on import order.

---

## Status

**785 tests passing** (784 with database isolation enforced), lint clean, frontend builds. Persistence, auth, the full
57-service catalogue, the analysis pipeline, governance and the API are working
end to end.

What remains is I/O at the edges — live provider sockets, the SMTP listener
binding, worker processes, and real detonation providers. Each sits behind an
interface that is already tested; see
[`server/docs/LAUNCH-GUIDE.md`](server/docs/LAUNCH-GUIDE.md).
