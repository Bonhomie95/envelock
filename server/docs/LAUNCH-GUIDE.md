# Envelock — Launch Guide

Everything left between today and taking real customers, in order. Each step
says **what**, **why**, and **exactly how**. Work top to bottom.

> Updated 21 September 2026 for: one repository (`Bonhomie95/envelock`), an
> IONOS VPS (4 vCores, 8 GB RAM, 240 GB NVMe), and the new setup script that
> builds the server for you. The code is tested — 785 server tests (784 again
> with database isolation enforced), 54 sensor tests, 24 web-app tests — and
> the whole server setup was run end to end, twice, on a fresh Ubuntu 24.04
> machine.

Steps marked 👤 are yours. Everything else is automated.

---

## Where things stand

| Area | State |
|---|---|
| Code | Done and tested. One repo: `server/`, `client/`, `admin/`. |
| Production server | **None yet.** You're buying an IONOS VPS; the setup script (step 5) builds it. |
| Email sending (Amazon SES) | Live and tested; carries over automatically. |
| Microsoft + Google sign-in keys | In your laptop's `server/.env`; carry over. Google must still review the app (step 12). |
| Stripe | Test key only (step 11). |
| Browser extension | Built; not yet in the stores (step 13). |
| Legal pages | Published; not yet lawyer-reviewed (step 15). |
| SMS alerts | Off. Optional (step 14). |

### Your checklist

- [ ] **Part A — before the server**
  - [ ] 1. 👤 Push the latest code
  - [ ] 2. 👤 Create the IONOS server
  - [ ] 3. 👤 Point your domain at it
- [ ] **Part B — build the server** (about 20 minutes, mostly waiting)
  - [ ] 4. 👤 Copy three files up
  - [ ] 5. 👤 Run the setup script
  - [ ] 6. 👤 Save the secrets it prints
  - [ ] 7. 👤 Create your operator account
  - [ ] 8. 👤 Prove it works end to end
- [ ] **Part C — before taking money**
  - [ ] 11. 👤 Stripe live
  - [ ] 12. 👤 Google and Microsoft app approval
  - [ ] 13. 👤 Publish the browser extension
  - [ ] 14. 👤 SMS alerts (optional)
  - [ ] 15. 👤 Lawyer review of the legal pages
  - [ ] 16. 👤 Off-server backups
- [ ] **Part D — test with real things**
  - [ ] 17. 👤 Try the add-ons in the real apps
  - [ ] 18. 👤 Connect real mailboxes
- [ ] **Part E — running it** (reference)
- [ ] **Part F — how many customers this server holds**
- Appendices: paste-ready text for Google's review (A), the extension stores
  (B), and your lawyer (C).

(Steps 9–10 are now done by the setup script; the numbers are kept so older
notes still line up.)

---

# Part A — Before the server

## 1. 👤 Push the latest code

**Why:** the server installs from GitHub, not from your laptop.

```bash
cd ~/Documents/DEV/web/envelock
git add -A
git commit -m "Monorepo CI, IONOS setup script, RLS fixes for background jobs"
git push
```

Then GitHub → your repo → **Actions**. Three workflows live at the repo root —
**Server**, **Web app**, **Admin console** — and each runs only when its own
folder changes. All three should go green.

## 2. 👤 Create the IONOS server

**Why:** nothing is running yet.

1. IONOS → **Servers & Cloud** → your new **VPS** (4 vCores / 8 GB / 240 GB).
2. **Image:** Ubuntu **24.04**, plain — *no* Plesk, cPanel or any other panel.
   A panel takes over ports 80/443 and fights nginx.
3. **Data centre:** a **US** location (Envelock is a US company; SES is in
   us-east-1).
4. **SSH key:** if IONOS offers to add one, paste your laptop's public key
   (`cat ~/.ssh/id_ed25519.pub` — create it first with `ssh-keygen -t ed25519`
   if it doesn't exist). Otherwise log in with the root password IONOS shows in
   the server's access details.
5. **Firewall:** Servers & Cloud → **Network → Firewall policies**. The
   server's policy must **allow TCP 22, 80 and 443**. Remove anything else it
   opened by default (commonly 8443/8447, which are Plesk's). The setup script
   also turns on the server's own firewall with the same three ports.

Write down the server's **public IPv4** — **`SERVER_IP`** below. IONOS VPS
addresses are fixed, so there's no "Elastic IP" step as on AWS.

Check you can log in: `ssh root@SERVER_IP`

## 3. 👤 Point your domain at it

In Cloudflare → `envelock.org` → **DNS**, set these **A** records to
`SERVER_IP`, proxy **off (grey cloud)** for now:

| Name | Type | Value | Proxy |
|---|---|---|---|
| `@` (envelock.org) | A | SERVER_IP | grey (DNS only) |
| `www` | A | SERVER_IP | grey |
| `app` | A | SERVER_IP | grey |
| `api` | A | SERVER_IP | grey |
| `admin` | A | SERVER_IP | grey |

Grey matters: the HTTPS certificate is issued by talking to your server
directly. You can turn the orange cloud on afterwards (end of step 5).

Leave the SES records (DKIM `CNAME`s, SPF `TXT`, `_dmarc`) exactly as they are.

Check from your laptop after a few minutes: `dig +short app.envelock.org`
should print `SERVER_IP`.

---

# Part B — Build the server

## 4. 👤 Copy three files up

From your laptop: the setup script, the settings generator, and your laptop's
`server/.env`. That file holds your working SES, Google, Microsoft, Safe
Browsing, IPinfo, OpenAI and VAPID keys, which carry over automatically.

```bash
cd ~/Documents/DEV/web/envelock/server
scp deploy/setup-server.sh deploy/make_prod_env.py .env root@SERVER_IP:/root/
```

The `.env` never goes through GitHub.

## 5. 👤 Run the setup script

```bash
ssh root@SERVER_IP
bash /root/setup-server.sh --email you@yourcompany.com
```

(The email is only for Let's Encrypt certificate-expiry notices.)

It works through 13 stages and prints a ✓ for each. **It stops once, at stage
5, for GitHub access.** It prints a line starting `ssh-ed25519 …`:

> On GitHub open **your repo `Bonhomie95/envelock` → Settings → Deploy keys →
> Add deploy key**. Paste the line, name it `envelock-server`, leave **Allow
> write access unticked**, save. Back on the server, press **Enter**.

A deploy key reads only this one repository and can't push — the safest access
to give a server.

What the stages do, so the output makes sense:

| Stage | Does |
|---|---|
| 1 | creates the `ubuntu` user (IONOS gives you only `root`; everything runs as `ubuntu`) and copies your SSH key to it |
| 2 | installs Python, Postgres 16, Redis, nginx, certbot, Node 22; adds 2 GB swap. **Waits** if the new server is still doing its own first-boot updates — normal, can take a few minutes |
| 3 | firewall: only 22, 80, 443 open |
| 4 | database + generated passwords, kept in `/root/envelock-secrets` |
| 5 | GitHub deploy key (the one pause) |
| 6 | clones the repo into `/home/ubuntu/apps` |
| 7 | writes the two settings files from your laptop `.env`: `.env` for the API (can lock mailbox passwords, **cannot** unlock them) and `.env.worker` for the worker (the only file holding the private key). Fresh session-signing secret, production values, isolation on |
| 8–9 | database tables; a restricted account for the app and a read-only one for backups (database isolation) |
| 10 | starts the API, the worker and the nightly backup timer; confirms isolation is enforced and the API can't decrypt |
| 11 | nginx with the security headers |
| 12 | HTTPS certificates for all five names |
| 13 | first deploy: builds the web app and admin console, backs up, migrates, restarts, verifies |

**If DNS wasn't ready in time,** stage 12 lists which names don't point at the
server yet and carries on. Once they do:

```bash
bash /root/setup-server.sh --tls-only --email you@yourcompany.com
```

**Re-running is safe** (tested). Every stage checks whether it's already done;
your settings files and database passwords are never regenerated once they
exist.

**Optional, once HTTPS works:** turn Cloudflare's proxy on (orange cloud) for
the five records and set Cloudflare → **SSL/TLS → Full (strict)**. Never
"Flexible".

## 6. 👤 Save the secrets it prints

Into your password manager:

1. The three database passwords: `cat /root/envelock-secrets`
2. The **credential private key** — the `ENVELOCK_CREDENTIAL_PRIVATE_KEY=` line
   in `/home/ubuntu/apps/server/.env.worker`. **Losing it means every customer
   must reconnect every mailbox.** It's the same key as on your laptop if your
   laptop `.env` had one; otherwise the script generated a new one and says so.

Then delete the plain-text copy: `rm /root/envelock-secrets`

From here on log in as `ubuntu`: `ssh ubuntu@SERVER_IP`

## 7. 👤 Create your operator account

```bash
cd ~/apps/server
./.venv/bin/python -m envelock.security.bootstrap_staff \
  --email you@envelock.org --name "Your Name" --department leadership
```

It prints a one-time password. Open `https://admin.envelock.org`, sign in, set
your own password and scan the QR code with an authenticator app. Open
**System status** and **Security**: everything green, isolation enforced, key
split.

(This command used to fail on a production database — isolation blocked it.
Fixed 21 Sep and covered by a test.)

## 8. 👤 Prove it works end to end

Each is something a customer does on day one:

1. **The sign-up email arrives at a domain you don't own.** Register at
   `https://app.envelock.org` with a work address at another company you
   control. The verification email must arrive — proof SES sends to everyone,
   not just your own addresses.
2. **Verify your domain** in the dashboard (a DNS `TXT` record).
3. **Connect a mailbox over IMAP**, press **Sync now** — synced within a minute.
4. **Scan my history** on it — completes.
5. **Run simulation** on the dashboard → **4/4 detected**.
6. **Add a device** in the sensor panel and pair the Thunderbird add-on or the
   Outlook add-in (step 17) — shows **live**.
7. `https://app.envelock.org/status` — everything operational.

If something fails:

```bash
journalctl -u envelock-api    -n 80 --no-pager
journalctl -u envelock-worker -n 80 --no-pager
```

---

# Part C — Before taking money

## 11. 👤 Stripe live

**Why:** your key is a test key (`sk_test_…`). Nobody can pay until it's live.

1. **Activate:** Stripe dashboard → **Activate payments** — business details,
   payout bank account, identity check. Can take a day.
2. **Products** (switch to **Live**, top right) → **Product catalogue → Add
   product**. Create four, each **Recurring · Monthly · USD**, and copy each
   **price ID** (`price_…`):

   | Product | Price | Pricing model |
   |---|---|---|
   | Envelock Essential | $25.00 | Flat rate |
   | Envelock Complete | $47.50 | Flat rate |
   | Envelock Essential — extra mailbox | $2.00 | Per unit |
   | Envelock Complete — extra mailbox | $3.50 | Per unit |

   Both plans include 5 mailboxes; the "extra mailbox" prices are what each
   one beyond that costs. The amounts must match the app
   (`server/src/envelock/billing/pricing.py`), or the page shows one price and
   Stripe charges another.
3. **API key:** **Developers → API keys** → **Secret key** (`sk_live_…`).
4. **Webhook:** **Developers → Webhooks → Add endpoint**
   - URL: `https://api.envelock.org/api/v1/billing/stripe/webhook`
   - Events (all six):
     `checkout.session.completed`,
     `checkout.session.async_payment_succeeded`,
     `checkout.session.async_payment_failed`,
     `customer.subscription.created`,
     `customer.subscription.updated`,
     `customer.subscription.deleted`
   - Copy the **Signing secret** (`whsec_…`).
5. **Customer portal:** **Settings → Billing → Customer portal** → turn on, and set:
   - **Cancellations:** allowed, **at end of billing period** (the terms promise
     this).
   - **Subscription updates / switch plans:** **off**. Plan and seat changes
     happen inside Envelock, which charges before granting; leaving them on in
     the portal is harmless (the webhook syncs them) but gives customers two
     places to do the same thing.
   - Payment methods and invoice history: on.
6. **Subscriptions → Settings (Manage failed payments):** retry per Stripe's
   default schedule, then **cancel the subscription**. The cancel fires
   `customer.subscription.deleted`, which moves the customer to Guard (free).
7. On the server, in **both** `~/apps/server/.env` and
   `~/apps/server/.env.worker` (`nano` to edit):

   ```
   ENVELOCK_STRIPE_SECRET_KEY=sk_live_...
   ENVELOCK_STRIPE_WEBHOOK_SECRET=whsec_...
   ENVELOCK_STRIPE_PRICE_ESSENTIAL=price_...
   ENVELOCK_STRIPE_PRICE_COMPLETE=price_...
   ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_ESSENTIAL=price_...
   ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_COMPLETE=price_...
   ```

   then `sudo systemctl restart envelock-api envelock-worker`
8. **Real-card test** on your own test workspace, then refund yourself in Stripe:
   - Billing → set 1 extra mailbox → checkout. With 3+ trial days left, Stripe
     shows **$0.00 due today** and a first charge on the trial end date.
   - Back in the app: Billing shows "CURRENT PLAN" and 6 mailboxes.
   - Set extra seats to 2 → **UPDATE**. Stripe → the customer → an invoice for
     the prorated seat appears.
   - Switch to Essential → the next invoice shows a credit.
   - Manage billing → cancel → at period end the workspace drops to Guard.

## 12. 👤 Google and Microsoft app approval

**Why:** "Connect with Google / Microsoft" works for you today; the public hits
warnings or a block until each provider reviews the app.

**Google — the long one, start now.** Envelock asks for `gmail.readonly` and,
for Workspace admins, `admin.reports.audit.readonly`. Gmail read access is a
**restricted scope**: Google requires app verification *and* an independent
security assessment (CASA) before anyone beyond your test users can connect.
Until then: at most 100 test users you add by hand, and their connection
expires every 7 days.

1. Google Cloud console → **APIs & Services → OAuth consent screen**: app
   name, logo, support email, links to `https://app.envelock.org/privacy` and
   `/terms`, authorised domain `envelock.org`.
2. **Credentials:** redirect URI exactly
   `https://api.envelock.org/api/v1/connect/oauth/google/callback`.
3. **Publish app → Submit for verification.** Paste the scope justifications
   from **Appendix A**; it also has a script for the demo video Google asks for.
4. Google then refers you to a CASA assessor. Budget weeks, and a fee.

**While you wait:** Gmail / Google Workspace customers connect **over IMAP with
an app password** — that path needs no Google approval.

**Microsoft:**

1. Azure portal → **Microsoft Entra ID → App registrations** → your app.
2. **Authentication:** redirect URI
   `https://api.envelock.org/api/v1/connect/oauth/microsoft/callback`;
   "Accounts in any organizational directory" selected.
3. **Branding & properties → Publisher verification:** link a Microsoft Partner
   Network (MPN) account. Without it customers see "unverified" and many
   companies' policies block the consent.
4. Each customer's IT admin grants admin consent once for their company.

## 13. 👤 Publish the browser extension

**Why:** until it's in the stores, the dashboard says "in review" and offers
only a manual install. Thunderbird and Outlook need no store.

On your laptop:

```bash
cd ~/Documents/DEV/web/envelock/client
npm run build:sensor
ls sensor/dist
```

1. **Chrome Web Store** (https://chrome.google.com/webstore/devconsole) —
   one-time US$5. **New item** → upload
   `sensor/dist/envelock-sensor-chrome-1.0.0.zip`. Fill the listing and privacy
   tabs from **Appendix B**.
2. **Microsoft Edge Add-ons**
   (https://partner.microsoft.com/dashboard/microsoftedge) — free. Same Chrome
   zip, same Appendix B text.
3. **Firefox** (https://addons.mozilla.org/developers) — free. Upload
   `sensor/dist/envelock-sensor-firefox-1.0.0.zip`. Mozilla's checker already
   passes it with 0 errors, 0 warnings.

Reviews take a day to a couple of weeks. As each is approved, add its link on
the server to `~/deploy/client.env` (create it; it survives every deploy):

```
VITE_SENSOR_CHROME_URL=https://chromewebstore.google.com/detail/...
VITE_SENSOR_EDGE_URL=https://microsoftedge.microsoft.com/addons/detail/...
VITE_SENSOR_FIREFOX_URL=https://addons.mozilla.org/firefox/addon/...
```

then `~/deploy/deploy.sh`.

**Updating later:** bump `client/sensor/version.json`, `npm run build:sensor`,
upload the new zips. **Never** change the `<Id>` in
`client/sensor/outlook/manifest.xml` — every Outlook install would stop
updating.

## 14. 👤 SMS alerts (optional)

SMS is the last alert rung, used only when a Critical alert isn't acknowledged
in time. It's **off**, which is fine: email and browser push still fire. To add
it with Twilio, buy a number and put in both env files:

```
ENVELOCK_SMS_ENABLED=true
ENVELOCK_SMS_PROVIDER=twilio
ENVELOCK_SMS_ACCOUNT_SID=AC...
ENVELOCK_SMS_API_KEY=<the auth token>
ENVELOCK_SMS_SENDER_ID=+1XXXXXXXXXX
```

then `sudo systemctl restart envelock-api envelock-worker`. Customers must
verify their phone number before any SMS goes to it.

## 15. 👤 Lawyer review of the legal pages

**Why:** `/terms`, `/privacy`, `/dpa` and `/subprocessors` are live. The facts
are accurate to the code; the contract wording has **not** been reviewed, and
the DPA page says so. Business customers will send it to their lawyers.

Send a US technology/privacy lawyer the brief in **Appendix C**. When they sign
off, remove the "pending counsel" notice in `client/src/pages/Legal.tsx`.

## 16. 👤 Off-server backups

**Why:** the nightly backup (03:20 UTC, kept 5 days) sits on the same disk as
the database. If the server dies, the backups die with it.

With IONOS **S3 Object Storage** (any S3-compatible storage works the same way):

1. IONOS → **Storage → S3 Object Storage** → create a bucket, e.g.
   `envelock-backups`, ideally in a **different region** from the server, and
   an **access key** for it. Note the bucket's **endpoint** hostname IONOS
   shows.
2. On the server:

   ```bash
   sudo apt install -y rclone
   rclone config create ionos s3 provider IONOS \
     access_key_id YOUR_KEY secret_access_key YOUR_SECRET \
     endpoint THE_ENDPOINT_IONOS_SHOWS
   echo 'ENVELOCK_BACKUP_REMOTE=ionos:envelock-backups/db' >> ~/apps/server/.env
   ~/apps/server/deploy/backup.sh --label first-remote
   ```

   The backup prints where it uploaded. Every nightly backup now goes there
   too. (Until 21 Sep the nightly job never read this setting from `.env`; fixed.)
3. **Prove a restore works** — restores the newest backup into a scratch
   database, checks it, drops it (tested: 33 tables restored):

   ```bash
   ~/apps/server/deploy/restore.sh --drill
   ```

   Put it on your calendar for the first Monday of each month.

---

# Part D — Test with real things

## 17. 👤 Try the add-ons in the real apps

The add-ons were tested against simulated versions of each app plus the real
API. This is the 15-minute check in the real ones, with a mailbox connected to
your test workspace.

**Chrome / Edge (before the store):** `chrome://extensions` → **Developer
mode** on → **Load unpacked** → `client/sensor/dist/chrome`. Click the Envelock
icon → **Pair** → type the code from the dashboard's sensor panel (**Add
device**). Open Gmail or Outlook on the web.
✅ The dashboard shows the device **live** within a minute; close the tab and
within ~3 minutes it isn't.

**Firefox:** `about:debugging` → **This Firefox** → **Load Temporary Add-on**
→ `client/sensor/dist/firefox/manifest.json`. Same checks.

**Thunderbird:** Tools → **Add-ons and Themes** → gear → **Install Add-on From
File** → `client/sensor/dist/envelock-sensor-thunderbird-1.0.0.xpi` → pair →
open a message. ✅ Live, and the open is recorded.

**Outlook (Microsoft 365 / on the web):** **Get Add-ins** → **My add-ins** →
**Add a custom add-in → Add from URL** →
`https://app.envelock.org/addins/outlook/manifest.xml`. Open a message, open the
Envelock pane, **pin it**, pair. ✅ Live.

Tell Claude exactly what you saw at any step that didn't match.

## 18. 👤 Connect real mailboxes

Fetching has been tested against a small fake mail server, never a real
provider. Try one of each:

- **A real IMAP mailbox** (any host that gives you IMAP; use an app password
  where offered).
- **Microsoft 365** — "Connect with Microsoft".
- **Google Workspace** — "Connect with Google" (as a test user, step 12).

For each: connect → **Sync now** → send it an email from elsewhere → confirm
it's analysed within a minute, **and that it still shows as unread in the real
inbox** — Envelock must never mark mail read.

Need a mailbox you fully control? `server/deploy/TEST_MAIL_SERVER.md` sets one
up (Postfix + Dovecot) — on a separate small server, not production.

---

# Part E — Running it

## Deploying a change

On your laptop: `git push`. On the server, as `ubuntu`:

```bash
~/deploy/deploy.sh
```

It pulls the repo, backs up, migrates, rebuilds, restarts **both** the API and
the worker, and checks each site. If anything is wrong it stops and leaves the
running version untouched. If it says "a newer deploy.sh is in the repo", run
the `cp` it prints.

(Until 21 Sep the worker restart failed about 4 times in 5 — the worker, which
reads mail, would have kept running the previous release after most deploys.
Fixed and verified on Ubuntu.)

## Logs

```bash
journalctl -u envelock-api    -f        # live API log
journalctl -u envelock-worker -f        # live worker log (mail checking)
sudo tail -f /var/log/nginx/error.log
```

## Uptime alerts

A free uptime monitor (UptimeRobot, Better Stack) on
`https://api.envelock.org/ready`, every minute, alerting your phone. Use
`/ready` — it fails when the database or Redis is down; `/health` doesn't.

## Rolling back

```bash
cd ~/apps && git log --oneline -5
git checkout <previous-good-commit>
cd server && ./.venv/bin/pip install -q . && sudo systemctl restart envelock-api envelock-worker
```

Back to normal with `git checkout main` and the next `~/deploy/deploy.sh`. If a
migration damaged data, the pre-deploy backup is the restore point:
`~/apps/server/deploy/restore.sh --list`, then the guarded
`restore.sh --PRODUCTION <file>` (take a fresh backup first).

## Before rotating any key

- **SECRET_KEY:** changing it signs everyone out; nothing else is lost.
- **Credential private key — never just replace it.** Generate a new pair
  (`./.venv/bin/python -m envelock.security.keygen`), put it in `.env.worker`
  while the old private key is still reachable, then run the migration with the
  worker's settings. The tool reads `.env` from the folder it runs in:

  ```bash
  mkdir -p ~/rotate && cp ~/apps/server/.env.worker ~/rotate/.env && chmod 600 ~/rotate/.env
  cd ~/rotate && ~/apps/server/.venv/bin/python -m envelock.security.rotate_credentials --migrate
  rm -rf ~/rotate
  ```

  Only when it reports **0 remaining** on the old key, drop the old one and put
  the new **public** key in `.env`. (Until 21 Sep, with isolation on, this tool
  saw zero credentials and would have reported "done" with nothing migrated.
  Fixed and covered by a test.)
- **VAPID keys:** never change them; it silently breaks every browser-push
  subscription.

## The read-flag notice (only if you restore old data)

Builds before 21 Sep marked new IMAP mail as read. The new server starts empty,
so **no notice is needed**. If you ever restore the old production database:

```bash
cd ~/apps/server
./.venv/bin/python -m envelock.ops.imap_read_notice --fixed-at 2026-09-21T00:00:00Z --show
```

(It sends nothing without `--send`.)

## Where each key comes from

| Key(s) | Where | Cost |
|---|---|---|
| `SECRET_KEY`, `METRICS_TOKEN`, DB passwords | generated by the setup script | free |
| `CREDENTIAL_PUBLIC/PRIVATE_KEY` | your laptop `.env`, or generated by the setup script | free |
| `SMTP_*` | Amazon SES → SMTP settings | ~$0.10 per 1,000 emails |
| `SMTP_RELAY_FALLBACK_DSN` | Mailjet (already set) | free tier |
| `MS_CLIENT_ID/SECRET` | Azure → Entra ID → App registrations | free |
| `GOOGLE_CLIENT_ID/SECRET`, `GOOGLE_PUBSUB_TOPIC` | Google Cloud → Credentials; Pub/Sub | free (CASA is paid) |
| `SAFEBROWSING_API_KEY` | Google Cloud → Safe Browsing API | free |
| `IPINFO_TOKEN` | ipinfo.io | free tier |
| `OPENAI_API_KEY` | platform.openai.com | pay per use, capped per mailbox |
| `VAPID_*` | already generated — never change | free |
| `STRIPE_*` | step 11 | 2.9% + 30¢ per charge |
| `SMS_*` | step 14 (optional) | per message |

---

# Part F — How many customers this server holds

Measured on 21 September, not guessed:

- **Detection:** ~8 ms of CPU per email on a fast core — allow ~20 ms on a VPS
  vCore. One worker handles ~50 emails a second, ~4 million a day. **Not the
  limit.**
- **Memory:** the API and the worker use ~115–150 MB each. With Postgres,
  Redis, nginx and the OS, the whole stack idles under 1.5 GB of your 8 GB.
  **Not the limit.**
- **The real limit is checking mailboxes for new mail.** Each mailbox is
  checked every 60 seconds, and each check is a network round trip to the
  customer's mail provider — roughly 0.5–1.5 s. Until 21 Sep the worker checked
  them **one at a time**, which capped it at ~40–100 mailboxes before new mail
  arrived late. It now checks **16 at once** on this server (and never more than
  15 at the same provider, which providers require).
- **Disk:** ~1.5 KB kept per email (metadata and rewritten links — not the
  email itself), for up to a year. A typical protected mailbox receives ~80
  emails a day → ~45 MB per mailbox per year, then flat.

A "customer" here is a business protecting **~5 mailboxes** (a typical small
company's finance and leadership inboxes).

| | Mailboxes | Businesses (~5 each) | New mail seen within |
|---|---|---|---|
| **Comfortable** | up to **~500** | **~100** | 1 minute, with headroom |
| **Maximum on this box** | ~**900** | **~180** | 1 minute, at the limit |
| Past that, unchanged | 1,000–2,000 | 200–400 | 2–3 minutes: slower, not broken |

Disk at the comfortable level: ~22 GB of database after a year, plus ~5 nightly
backups ≈ **~50 GB of 240 GB**.

**How to tell you're getting close:** the worker logs how long each check cycle
takes.

```bash
journalctl -u envelock-worker --no-pager | grep "imap poll cycle took" | tail -3
```

`took 12.3s of 60s` is healthy. **Past ~45s, you're near the limit.**

**When to move to AWS or a bigger box:** past **~400 mailboxes**, or cycles over
45 s — whichever comes first. That's when to move the database to its own
managed server (e.g. RDS) and give the worker its own machine. The code already
supports both; it's a settings change, not a rewrite.

Two dials for more headroom before moving (in `.env.worker`, then
`sudo systemctl restart envelock-worker`):

```
ENVELOCK_IMAP_POLL_CONCURRENCY=24     # 16 → 24 checks at once (~1,400 mailboxes)
ENVELOCK_DB_POOL_SIZE=30               # keep this above the concurrency
```

---

# Appendix A — Google verification: paste-ready answers

**Scope justification — `https://www.googleapis.com/auth/gmail.readonly`**

> Envelock protects businesses from invoice and payment fraud (business email
> compromise). With the mailbox owner's consent it reads incoming messages to
> detect impersonation, changed bank details, lookalike sender domains and
> malicious links, and alerts the business before a payment is made. It does
> not send, delete or modify mail, and never uses message content for
> advertising or model training. Read-only access is the minimum that allows
> each new message to be checked as it arrives.

**Scope justification — `https://www.googleapis.com/auth/admin.reports.audit.readonly`**

> Requested only when a Google Workspace administrator connects their
> organisation. Envelock reads sign-in audit events to detect account takeover
> (for example a sign-in from a new country followed by a forwarding rule),
> which precedes most payment-redirection fraud. Envelock never writes to the
> admin console or changes any setting.

**Demo video (2–3 minutes, unlisted YouTube link):**
1. Show `app.envelock.org`, sign in, open **Connect mailbox → Connect with Google**.
2. Show Google's consent screen with the app name and scopes clearly visible.
3. After consent, show the mailbox appear as connected.
4. Send a test invoice email; show Envelock's alert and verdict on it.
5. Show removing the mailbox, and say that removing it deletes the stored access.

---

# Appendix B — Browser extension listing: paste-ready

**Name:** Envelock Sensor

**Short description (≤132 characters):**
> Lets Envelock tell when you really are reading your mail — so a sign-in from anywhere else stands out.

**Full description:**
> The Envelock Sensor works with your company's Envelock account to catch
> account takeover early. While your webmail is open, it tells Envelock this
> device is present; when you open a message, it confirms the read was yours.
> If mail is read while none of your devices are present, Envelock alerts your
> team — often the first sign someone else is in your mailbox.
>
> Pairing: create a one-time code in your Envelock dashboard and enter it here.
> The sensor never sees your password and cannot read your Envelock alerts.
>
> Privacy: the sensor sends only the mailbox address, this device's presence,
> and the Message-ID header of messages you open — never message content.
> Requires an Envelock account.

**Category:** Productivity (Chrome/Edge) · Privacy & Security (Firefox)

**Single purpose (Chrome):**
> Report the mailbox owner's presence and message opens to their Envelock
> account so unauthorised mailbox access can be detected.

**Permission justifications:**
- `storage` — keeps this device's pairing and settings on the device.
- `alarms` — sends a presence heartbeat once a minute while webmail is open.
- `scripting` — adds the small presence script to a self-hosted webmail page,
  only after the user grants access to that one address when pairing.
- Host access to `mail.google.com`, `outlook.office.com`, `outlook.office365.com`
  and `outlook.live.com` — detects when the webmail is open and which message
  is being read; nothing else on the page is read or sent.
- Host access to `api.envelock.org` — Envelock's own server, where the reports go.
- Optional access to other sites — requested only if the user pairs a
  self-hosted webmail, and only for that one address.

**Data usage (Chrome privacy tab):** collects "Personally identifiable
information" (the mailbox address) and "Website activity" (webmail open /
message opened); used only to provide the service; not sold; not transferred
for unrelated purposes; not used for creditworthiness or lending.

**Privacy policy URL:** `https://app.envelock.org/privacy`

---

# Appendix C — Brief for the lawyer

> Envelock, Inc. sells a B2B email-fraud protection service. Customers connect
> company mailboxes (IMAP credentials, or Microsoft/Google OAuth); we read
> inbound mail to detect payment fraud and account takeover, and alert the
> customer. We keep message metadata up to 12 months, alerts up to 24 months,
> and message bodies at most 30 days. Mailbox credentials are encrypted, and
> only our mail worker can decrypt them — our internet-facing API cannot.
>
> Our published pages — `/terms`, `/privacy`, `/dpa`, `/subprocessors` at
> app.envelock.org — were drafted by engineering and are accurate about what
> the system does. We need counsel to review and correct: limitation of
> liability and warranties; governing law and venue; the DPA including standard
> contractual clauses for EU/UK customers; the subprocessor list and change
> notice terms; and anything specific to acting on payment-fraud alerts. We
> sell to US businesses first, then internationally.
