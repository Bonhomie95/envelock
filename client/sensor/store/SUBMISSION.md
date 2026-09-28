# Publishing the Envelock Sensor

Everything paste-ready is in **`server/docs/LAUNCH-GUIDE.md` → Appendix B**
(name, descriptions, single purpose, permission justifications, data-usage
answers). This file is the mechanics: accounts, files, and the things that get
a first submission rejected.

## Files to upload

| Store | File | Built by |
|---|---|---|
| Chrome Web Store | `client/public/downloads/envelock-sensor-chrome.zip` | `npm run build:sensor` |
| Microsoft Edge Add-ons | the same Chrome zip | — |
| Firefox (AMO) | `client/public/downloads/envelock-sensor-firefox.zip` | — |
| Thunderbird (ATN) | `client/public/downloads/envelock-sensor-thunderbird.xpi` | — |

Screenshots: `client/sensor/store/screenshots/*.png` (1280×800, accepted by all
three browser stores).

Privacy policy `https://envelock.org/privacy` · Terms `https://envelock.org/tos`
— both required, both served from the apex.

## Accounts

| Store | Cost | Notes |
|---|---|---|
| Chrome Web Store | **$5 once** | Register at chrome.google.com/webstore/devconsole |
| Edge Add-ons | free | partner.microsoft.com/dashboard/microsoftedge |
| Firefox AMO | free | addons.mozilla.org/developers |
| Thunderbird ATN | free | addons.thunderbird.net |

Use **admin@envelock.org**, not a personal account. A store listing tied to
someone's personal login is a problem the first time that person is on holiday.

## What gets a first submission rejected

1. **Unjustified permissions.** Every one must be explained in the review notes.
   `optional_host_permissions: ["https://*/*"]` is the one they will ask about —
   the answer is in Appendix B: it is requested only when a customer pairs a
   self-hosted webmail, and only for that one address. Say it before they ask.
2. **Screenshots that are not the product.** Ours frame the real built
   `options.html`; keep it that way.
3. **A privacy policy that does not mention the extension.** Ours does, at the
   apex, and it loads without a redirect — Microsoft's and Google's fetchers
   both dislike a policy URL that 301s to another hostname.
4. **Data-usage answers that contradict the code.** We declare personally
   identifying information (the mailbox address) and website activity. That
   matches `manifest.firefox.json`'s `data_collection_permissions`. If one
   changes, change both.
5. **A login wall with no way in.** Reviewers cannot test an extension that
   needs a paired account. Give them a test tenant and a pairing code in the
   review notes, and say the extension is inert until paired.

## Review notes to paste

> The Envelock Sensor reports only presence and message-open events to the
> account the user pairs it with; it is inert until paired. To test: sign in at
> https://app.envelock.org with the credentials below, open a mailbox, choose
> "Add a device", and enter the code the dashboard shows into the extension's
> options page.
>
> Test account: <email> / <password>
>
> The extension reads no message content, no credentials and no site other than
> the one webmail the user selects.

Create that test account before submitting, and leave it live — reviewers come
back on updates.

## After approval

Put the store URLs into the client so the dashboard links to the stores instead
of offering a side-load zip: `VITE_SENSOR_CHROME_URL`, `VITE_SENSOR_EDGE_URL`,
`VITE_SENSOR_FIREFOX_URL`, read in `client/src/components/SensorPanel.tsx`.

On the server they go in **`~/deploy/client.env`** — deliberately outside the
repo, because `deploy.sh` rewrites `client/.env.production` on every deploy and
appends that file. Anything put directly in `.env.production` is erased on the
next deploy.

```bash
cat >> ~/deploy/client.env <<'ENV'
VITE_SENSOR_CHROME_URL=https://chromewebstore.google.com/detail/<id>
VITE_SENSOR_EDGE_URL=https://microsoftedge.microsoft.com/addons/detail/<id>
VITE_SENSOR_FIREFOX_URL=https://addons.mozilla.org/firefox/addon/envelock-sensor/
ENV
~/deploy/deploy.sh
```

Until they are set the sensor panel offers the manual side-load zip, which is
correct but is also why Complete's two sensor-dependent features are hard to
sell — asking someone to enable Developer mode is not a purchase flow.
