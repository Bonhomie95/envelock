# Envelock sensor

The small piece of Envelock that runs where people actually read their mail.
It tells the Envelock API two things about one mailbox, and nothing else:

- **this device is here** — `POST /api/v1/sensor/heartbeat`, once a minute while
  the mail client is open
- **the owner opened this message** — `POST /api/v1/sensor/message-opened`, with
  the message's `Message-ID` where the client can see it

From those the server raises the Complete plan's account-takeover alerts: a
sign-in from a new device or country (C7/C8/C10), and a message read while none
of the owner's devices were present (C11). See the dashboard's `/docs#sensor`
for the customer-facing explanation, and `server/src/envelock/platform/sensor.py`
for the server's rules.

| Client | Folder | What it can attest | Distribution |
|---|---|---|---|
| Browser extension (Chrome, Edge, Firefox) | `browser/` | Webmail open; the exact message on Roundcube-style webmail, "owner is reading" on Gmail / Outlook on the web | Chrome Web Store, Edge Add-ons, addons.mozilla.org |
| Thunderbird add-on | `thunderbird/` | The exact message, whenever Thunderbird runs | `.xpi` served by the dashboard (Thunderbird needs no store) |
| Outlook add-in | `outlook/` | The exact message, while the pane is pinned | Manifest URL served by the dashboard |

All three load **one** shared core, `core/envelock-sensor.js`. It has no
`import`/`export`, so it is at once a classic script (extension backgrounds, the
Outlook pane) and an ES module (the Node tests) — nothing to build, nothing to
drift.

## Security properties worth keeping

- **The sensor never holds a person's session.** It trades a one-time pairing
  code from the dashboard for its own token, which can only report for one
  mailbox and one device. Stolen, it can post heartbeats; it cannot read a
  single alert (`test_a_sensor_token_cannot_read_anything`).
- **The token is pinned to a random device id** the client generates, so one
  token cannot pose as many devices. A copied browser profile replayed from
  elsewhere shows up as the same device on a new network, which the server
  treats as a new sign-in.
- **Outlook stores the token in `localStorage`, never roaming settings** —
  roaming settings live inside the mailbox, where an intruder could read the
  token and forge the very attestations meant to catch them.
- **No message content, ever.** Only the `Message-ID` header, and on Roundcube
  only the header block of the raw source is parsed.
- **Least privilege.** The browser extension's broad `https://*/*` is optional
  and requested per webmail origin at pairing time; Gmail and Outlook on the web
  are the only sites it can see by default. `test/package.test.mjs` enforces it.

## Commands

From `client/`:

```bash
npm run build:sensor        # build all four into sensor/dist/ and publish to public/
npm run build:sensor:dev    # same, but also allows http://localhost as the server
npm run test:sensor         # the sensor's own test suite (Node's built-in runner)
npm run build               # runs build:sensor first, so every deploy ships it
```

Wire test against a real local API (dev mode, domain verification off):

```bash
ENVELOCK_E2E_API=http://127.0.0.1:8011 node sensor/scripts/e2e-local.mjs
```

Packages are byte-for-byte reproducible: the ZIP writer in `scripts/build.mjs`
uses fixed timestamps, so a store reviewer can rebuild and compare.

## Publishing — the owner's steps

The version lives in one place, `version.json`; bump it, then
`npm run build:sensor`. Upload the versioned files from `sensor/dist/`.

**Before any upload**, run the vendors' own validators once — they catch what a
store review would otherwise take days to report:

```bash
npx web-ext lint --source-dir sensor/dist/firefox
npx web-ext lint --source-dir sensor/dist/thunderbird
npx office-addin-manifest validate sensor/dist/outlook/manifest.xml
```

1. **Chrome Web Store** — developer account (one-time US$5), upload
   `envelock-sensor-chrome-<v>.zip`. Privacy tab: data collected is "website
   activity" (webmail open / message opened) and "personally identifiable
   information" (the mailbox address), used only to provide the service. Then
   set `VITE_SENSOR_CHROME_URL` in the client's production env.
2. **Edge Add-ons** — Partner Center, same zip. Set `VITE_SENSOR_EDGE_URL`.
3. **Firefox** — addons.mozilla.org, upload `envelock-sensor-firefox-<v>.zip`.
   The manifest declares `data_collection_permissions`, which AMO requires of new
   extensions. Set `VITE_SENSOR_FIREFOX_URL`.
4. **Thunderbird** — nothing to publish; the dashboard serves the `.xpi`. Listing
   it on addons.thunderbird.net is optional (it adds auto-updates).
5. **Outlook** — nothing to publish; the dashboard serves the manifest at
   `https://app.envelock.org/addins/outlook/manifest.xml`. Customers' IT deploys
   it from the Microsoft 365 admin centre with that URL. AppSource listing is
   optional. **Never change the `<Id>` in `outlook/manifest.xml`** — Outlook
   treats a new Id as a different add-in and every install stops updating.

Until a store URL is set, the dashboard says plainly that the browser extension
is in review and offers the unpacked-load route for a pilot — it never links a
placeholder.

## Deploying the Outlook pane

`/addins/outlook/` is served by the app host with its own security headers
(`server/deploy/nginx/headers-addin.conf`): Outlook frames the pane and it loads
Microsoft's `office.js`, neither of which the dashboard's policy permits — and
the dashboard's policy is not loosened to make room.

## Honest limits

- A flag can only show the first read of mail that was sitting unread.
  Re-reading, or reading within one poll interval of arrival, is invisible to C11.
- The Outlook add-in reports only while its pane is pinned; Outlook gives
  add-ins no background process.
- Classic Outlook does not load add-ins for plain IMAP accounts. Those customers
  use Thunderbird or the browser extension.
- Gmail and Outlook on the web do not expose the `Message-ID` in the page, so
  there the extension attests "the owner is reading" rather than a specific
  message.
