# A real test mail server on the same VPS

Goal: a genuine IMAP mailbox you control, on this same machine, so you can
connect it to Envelock and watch the whole pipeline work on real messages —
discovery, connection, ingestion, detection, alerting.

---

## First: not Virtualmin. Here is why

Virtualmin would work on a bigger machine, but on *this* one it will break what
you have already built. Three specific reasons, not preferences:

**1. It barely fits in your RAM, and "barely" is the problem.** You have 4 GB
total, already running PostgreSQL, Redis, nginx and the Envelock API. Virtualmin
recommends 4 GB *for itself*, because its installer pulls in ClamAV (which alone
wants ~1 GB resident), SpamAssassin, MariaDB, BIND and more. Two things that each
want most of the machine do not add up to one that works: the likely outcome is
the kernel's out-of-memory killer choosing a process, and it tends to pick the
largest — which is PostgreSQL. It will happen during a frontend build, when Vite
briefly wants 2 GB of its own.

**2. It wants to own your web server.** Virtualmin installs and manages Apache
(or its own nginx configuration) on ports 80 and 443. Those ports are currently
serving `app.envelock.org` and `admin.envelock.org` from configs you just wrote.
At best they conflict; at worst Virtualmin rewrites them.

**3. You would use about 2% of it.** Virtualmin is a shared-hosting control panel
— billing, FTP accounts, DNS zones, website provisioning. You need one mailbox.

**What you actually need is Postfix + Dovecot**, which is what Virtualmin would
have installed underneath anyway, minus everything else. Together they use around
50 MB of RAM.

---

## Two things that will bite you if nobody warns you

### 1. AWS blocks outbound port 25 — permanently, by default

Every EC2 instance has outbound port 25 blocked to fight spam. You can request
removal through a support form, but AWS frequently declines for newer accounts.

**What this means in practice:**

| Direction | Port | Works? |
|---|---|---|
| Receiving mail from the internet | 25 inbound | ✅ Yes |
| Injecting your own test messages | local | ✅ Yes |
| Sending mail out to Gmail, etc. | 25 outbound | ❌ Blocked |

This is fine for what you are doing. Envelock needs to **read** a mailbox, not
send from it. Keep using a transactional relay (Postmark, Mailgun, SES) for
Envelock's own outgoing alerts and password resets — those go over port **587**,
which AWS does **not** block.

### 2. Envelock will reject a self-signed certificate — deliberately

This is the one that would waste your afternoon. Envelock connects with
`imaplib.IMAP4_SSL` using Python's default TLS context, which **verifies the
certificate and the hostname** ([imap_probe.py:158](../src/envelock/channels/mail/imap_probe.py)).
Dovecot ships with a self-signed "snakeoil" certificate, and Envelock will refuse
it with a certificate-verification error.

That refusal is correct behaviour, not a bug to work around. Silently accepting
an unverified certificate is precisely how a mailbox password gets handed to a
machine-in-the-middle, and this product exists to prevent that.

So we give Dovecot a **real Let's Encrypt certificate**. You already have certbot
installed, so this costs one extra command.

---

## The plan

```
  Internet ──25──► Postfix ──► /home/victim/Maildir ◄── Dovecot ──993──► Envelock
                                                                          (same box,
                                                                       via /etc/hosts)
```

We will use a **separate subdomain for test mail** — `test.envelock.org` — so
that `envelock.org` itself stays free for real company email later. Envelock
allows this: its domain check reduces `test.envelock.org` to the registrable
domain `envelock.org`, so once you have verified `envelock.org` in the dashboard,
a mailbox at `victim@test.envelock.org` is permitted.

---

## Step 1 — DNS records

In Cloudflare, add these. **All three must be grey cloud (DNS only)** — Cloudflare
proxies HTTP, not mail, and an orange cloud on a mail record silently breaks it.

| Type | Name | Value | Priority |
|---|---|---|---|
| A | `mail` | `52.55.69.223` | — |
| MX | `test` | `mail.envelock.org` | 10 |
| TXT | `test` | `v=spf1 a:mail.envelock.org -all` | — |

**Check it worked** (from your laptop, after a few minutes):

```bash
dig +short mail.envelock.org && dig +short MX test.envelock.org
```

You want `52.55.69.223` — **your real IP, not a Cloudflare address**. If you see
`104.21.x.x`, the record is still orange-clouded; switch it to DNS only.

---

## Step 2 — Open port 25 inbound on AWS

EC2 Console → your instance → **Security** tab → security group → **Edit inbound
rules** → **Add rule**:

| Type | Port | Source |
|---|---|---|
| Custom TCP | 25 | Anywhere-IPv4 (`0.0.0.0/0`) |

It has to be open to everyone, because you cannot know in advance which mail
server will deliver to you.

**Do not open port 993.** Envelock reaches Dovecot without leaving the machine
(Step 6 arranges this), so there is no reason to expose a password-authenticated
IMAP server to the internet, where it would start receiving brute-force attempts
within hours.

---

## Step 3 — Install Postfix and Dovecot

```bash
sudo apt update
sudo apt install -y postfix dovecot-imapd dovecot-lmtpd swaks
```

A blue configuration screen appears:

- **General type of mail configuration** → choose **Internet Site**
- **System mail name** → type `mail.envelock.org`

(`swaks` is a mail-sending tool we will use in Step 8 to craft realistic test
messages.)

**Check it worked:**

```bash
systemctl is-active postfix dovecot
```

Both should print `active`.

---

## Step 4 — Get a real certificate for the mail server

```bash
sudo certbot certonly --nginx -d mail.envelock.org
```

This works because `mail.envelock.org` points straight at your server with no
Cloudflare proxy in the way.

**Check it worked:**

```bash
sudo ls -l /etc/letsencrypt/live/mail.envelock.org/
```

You should see `fullchain.pem` and `privkey.pem`.

---

## Step 5 — Configure Dovecot

**Dovecot 2.4 (which Ubuntu 26.04 ships) renamed most of these settings**, and a
2.3-style config makes it refuse to start. Rather than guess, this writes the
right syntax for whichever version you have, validates it, and only restarts if
the validation passes — so a bad config can never take mail down.

```bash
cat <<'SCRIPT' > /tmp/dovecot-setup.sh
set -uo pipefail
CONF=/etc/dovecot/conf.d/99-envelock-test.conf
CERTDIR=/etc/letsencrypt/live/mail.envelock.org

dovecot --version || exit 1
VER="$(dovecot --version | cut -d. -f1,2)"
echo "Dovecot series: $VER"

sudo test -f "$CERTDIR/privkey.pem" || {
  echo "No certificate yet — run Step 4 first."; exit 1; }

case "$VER" in
  2.4|2.5|3.*)
    sudo tee "$CONF" >/dev/null <<EOF
dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0

protocols = imap

mail_driver = maildir
mail_path = ~/Maildir

ssl = required
ssl_server_cert_file = $CERTDIR/fullchain.pem
ssl_server_key_file = $CERTDIR/privkey.pem

auth_allow_cleartext = no

# INBOX is the maildir root itself (Maildir++ layout), not a separate folder.
# Two ways to get this wrong, and both were hit on a real deployment:
#   * Ubuntu ships mail_inbox_path = /var/mail/%{user}, so Dovecot tries to
#     create INBOX as an mbox in a directory the user cannot write —
#     "Failed to autocreate mailbox: Permission denied", surfacing to the
#     client as a bare [SERVERBUG].
#   * Setting it EMPTY does not restore the default on 2.4: Dovecot then
#     treats INBOX as an ordinary folder and creates ~/Maildir/.INBOX/,
#     which is a second, permanently empty mailbox while Postfix keeps
#     delivering to ~/Maildir/new/.
# Name the path explicitly.
mail_inbox_path = ~/Maildir
EOF
    ;;
  *)
    sudo tee "$CONF" >/dev/null <<EOF
protocols = imap
mail_location = maildir:~/Maildir

ssl = required
ssl_cert = <$CERTDIR/fullchain.pem
ssl_key  = <$CERTDIR/privkey.pem

disable_plaintext_auth = yes
auth_mechanisms = plain login

mail_inbox_path = ~/Maildir
EOF
    ;;
esac

if sudo doveconf -n >/dev/null 2>/tmp/dc.err; then
  echo "config valid — restarting"
  sudo systemctl restart dovecot && sudo systemctl is-active dovecot
else
  echo "INVALID, not applied. Error:"; cat /tmp/dc.err
  exit 1
fi
SCRIPT
bash /tmp/dovecot-setup.sh
```

**Check it worked.** First, that Dovecot is actually listening:

```bash
sudo ss -lntp | grep -E '993|imap'
```

Then ask it for its certificate. Connect to `127.0.0.1` — not
`mail.envelock.org`, which does not point at this machine yet (that is Step 6)
and whose port 993 is deliberately closed at AWS. The `-servername` flag still
asks for the right certificate by name:

```bash
openssl s_client -connect 127.0.0.1:993 -servername mail.envelock.org </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
```

> Paste that as **one line**. If your terminal wraps it, `-servername` loses its
> value and openssl complains that the option "needs a value".

You want `issuer=... Let's Encrypt ...`. If it says `snakeoil`, Dovecot did not
pick up the new config.

> **If Dovecot refuses to start**, the message from `systemctl status dovecot`
> names the setting it did not understand. The single most common cause on a new
> Ubuntu is a 2.3-era directive: `ssl_cert` became `ssl_server_cert_file`, and
> `mail_location` split into `mail_driver` plus `mail_path`.

## Step 6 — Make Envelock reach Dovecot without leaving the machine

Envelock will look up `mail.envelock.org` and try to connect. Left alone, that
resolves to your public IP and the connection loops out to the internet and back,
which is both slower and needs port 993 exposed.

This one line makes it connect straight to itself — while still presenting the
hostname `mail.envelock.org`, so the certificate check still passes:

```bash
echo '127.0.0.1  mail.envelock.org' | sudo tee -a /etc/hosts
```

**Check it worked:**

```bash
getent hosts mail.envelock.org
```

Should print `127.0.0.1  mail.envelock.org`.

### Step 6b — let Envelock dial a loopback address

Envelock refuses to connect to loopback and private addresses. That guard is not
incidental: the host and port come straight from a form, so without it the
connect test is a port scanner pointed at whatever the API can reach — including
the cloud metadata service. It is why you will otherwise see:

> “mail.envelock.org” resolves to loopback, which we will not connect to.

For a test mailbox on this same machine, allow it explicitly:

```bash
echo 'ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS=true' | sudo tee -a /home/ubuntu/apps/server/.env
sudo systemctl restart envelock-api
```

> **Turn this off when you finish testing.** It is deployment-wide, not
> per-mailbox: while it is on, any tenant can point the connect form at internal
> addresses. On a box with real customers that is a genuine hole, and the only
> reason it is acceptable here is that the box is yours and the window is short.
>
> ```bash
> sudo sed -i '/IMAP_ALLOW_PRIVATE_HOSTS/d' /home/ubuntu/apps/server/.env
> sudo systemctl restart envelock-api
> ```

> This only affects lookups made *on this server*. The rest of the world still
> resolves `mail.envelock.org` to your public IP and can deliver mail normally.

---

## Step 7 — Tell Postfix which domain to accept, and create the mailbox

```bash
sudo postconf -e 'mydestination = mail.envelock.org, test.envelock.org, localhost'
sudo postconf -e 'home_mailbox = Maildir/'
sudo postconf -e 'inet_interfaces = all'
sudo systemctl restart postfix
```

Create the test user. Choose a strong password when prompted — you will paste it
into Envelock:

```bash
sudo adduser --gecos "" victim
```

**Check you are not running an open relay.** This is important: an open relay
gets discovered and abused within a day, and gets your IP blacklisted.

```bash
postconf mynetworks && postconf smtpd_relay_restrictions
```

`mynetworks` should list only loopback and private ranges. `smtpd_relay_restrictions`
should include `reject_unauth_destination`. Both are the Debian defaults, so if
you chose "Internet Site" earlier they will already be correct.

---

## Step 8 — Put a test message in the mailbox

`swaks` lets you craft exactly the message you want to test against — including
the spoofed sender and lookalike domain that Envelock is built to catch.

A plain delivery first, to prove the plumbing:

```bash
swaks --to victim@test.envelock.org --from colleague@example.com \
      --server 127.0.0.1 --header "Subject: Plain test message" \
      --body "Just checking delivery works."
```

**Check it worked:**

```bash
sudo ls -l /home/victim/Maildir/new/
```

There should be a file in there. If `Maildir` does not exist at all, the message
did not deliver — check `sudo tail -30 /var/log/mail.log`, which names the reason.

Now something worth detecting — a display-name spoof, the most common opening
move in business email compromise:

```bash
swaks --to victim@test.envelock.org \
      --from "accounts@examp1e-corp.com" \
      --h-From: '"Finance Director" <accounts@examp1e-corp.com>' \
      --server 127.0.0.1 \
      --header "Subject: Updated bank details for this month's invoice" \
      --body "Hi, please note our account has changed. Kindly send this month's payment to the new details attached. Confirm once done — I am travelling and hard to reach by phone."
```

Note `examp1e-corp.com` — a digit `1` where an `l` belongs. That is the
lookalike-domain pattern the detection layer scores.

---

## Step 9 — Connect it to Envelock

1. In the dashboard, verify `envelock.org` under **Domains** first if you have
   not already. Mailbox connection is gated on it.
2. Go to **Mailboxes** → **Add mailbox**.
3. Enter the address: `victim@test.envelock.org`

Envelock will try to discover the server itself — this is worth watching, because
it exercises the real discovery ladder. It looks up the MX record for
`test.envelock.org`, finds `mail.envelock.org`, and offers port 993 with TLS.

If it asks for details, enter them manually:

| Field | Value |
|---|---|
| IMAP host | `mail.envelock.org` |
| Port | `993` |
| Security | SSL/TLS |
| Username | `victim` |
| Password | the password from Step 7 |

**Check it worked:** the mailbox should move to connected, and within a poll cycle
the two messages from Step 8 should appear — with the second one raising a
finding.

If the connection fails, the error message is written to be specific. Watch what
the API actually says while you try:

```bash
sudo journalctl -u envelock-api -f
```

---

## Optional: open the test mailbox in a Mac mail client

Useful for seeing what Envelock sees. Port 993 is closed at AWS on purpose, so
rather than exposing it, tunnel it over the SSH connection you already have.

**1. On your Mac**, point the mail hostname at the tunnel:

```bash
echo '127.0.0.1  mail.envelock.org' | sudo tee -a /etc/hosts
```

This is what makes the certificate check pass. Without it you would connect to
`localhost`, the certificate says `mail.envelock.org`, and every mail client
would throw a certificate warning — training you to click through exactly the
warning this product exists to take seriously.

**2. Open the tunnel** and leave the terminal running:

```bash
ssh -i /path/to/your-key.pem -N -L 9993:127.0.0.1:993 ubuntu@52.55.69.223
```

Port 9993 rather than 993 avoids needing `sudo` — anything below 1024 is
privileged on macOS. The port number does not affect certificate validation,
which checks the hostname only.

**3. Verify before touching the mail client** (new terminal tab):

```bash
openssl s_client -connect mail.envelock.org:9993 -servername mail.envelock.org </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
```

You want `issuer=... Let's Encrypt ...`. If this fails, the tunnel is not up —
fix that before blaming the mail client.

**4. Add the account.** Apple Mail: **Mail → Add Account → Other Mail Account**,
then correct the server details it guesses wrongly under **Advanced**. Thunderbird
is less fussy — it offers manual configuration directly.

| Setting | Value |
|---|---|
| Account type | IMAP |
| Incoming server | `mail.envelock.org` |
| Port | `9993` |
| Connection security | SSL/TLS |
| Authentication | Normal password |
| Username | `victim` |
| Password | the one you set with `adduser` |
| Outgoing (SMTP) | leave blank — this mailbox is for receiving only |

Apple Mail insists on an outgoing server. Give it the same host and let it fail;
you are not sending from this account.

**When you are done**, close the tunnel with Ctrl+C and remove the hosts line —
otherwise `https://mail.envelock.org` will not load in your Mac browser:

```bash
sudo sed -i '' '/mail.envelock.org/d' /etc/hosts
```

### The simpler alternative, and its cost

You could instead open port 993 in the AWS security group with **Source: My IP**.
No tunnel, no hosts file. Two downsides: your home IP address changes, so it
stops working without warning; and a password-authenticated IMAP server becomes
reachable from that address range. The tunnel avoids both and costs one extra
terminal window.

---

## When you are finished testing

A mail server that is not being watched is a liability. When you no longer need
it:

```bash
# Stop accepting mail from the internet
sudo systemctl stop postfix dovecot
sudo systemctl disable postfix dovecot
```

Then remove the port 25 inbound rule from your AWS security group, and delete the
`test` MX record.

---

## Troubleshooting

**`certificate verify failed` when connecting the mailbox** — Dovecot is still
serving the self-signed certificate. Re-run the check at the end of Step 5.

**`hostname mismatch`** — you connected to `localhost` or an IP instead of
`mail.envelock.org`. The certificate is only valid for that name; use it exactly.

**Connection times out** — Step 6's `/etc/hosts` line is missing, so it is trying
to reach your public IP on a port that is closed. Re-check with
`getent hosts mail.envelock.org`.

**Mail never arrives from outside** — port 25 inbound is not open, or the MX
record is orange-clouded in Cloudflare. `sudo tail -50 /var/log/mail.log` shows
whether anything is even reaching Postfix.

**Envelope certificate renewal** — certbot renews `mail.envelock.org`
automatically, but Dovecot keeps the old certificate in memory until restarted.
Add a reload hook once:

```bash
echo 'systemctl reload dovecot postfix' | sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-mail.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-mail.sh
```

Without this, mail connections start failing 90 days from now for a reason that
will be genuinely hard to guess at.

---

## Optional: test the forwarding ingestion path too

Envelock has a second way to receive mail — customers forward to a per-tenant
address at `in.envelock.org`, handled by its own SMTP listener on port **2525**
(`ENVELOCK_INGEST_SMTP_PORT`). That does not collide with Postfix on 25, so both
can run together.

To test it, point an MX record for `in.envelock.org` at `mail.envelock.org` and
have Postfix hand that domain to Envelock:

```bash
sudo postconf -e 'relay_domains = in.envelock.org'
sudo postconf -e 'transport_maps = hash:/etc/postfix/transport'
echo 'in.envelock.org  smtp:[127.0.0.1]:2525' | sudo tee /etc/postfix/transport
sudo postmap /etc/postfix/transport
sudo systemctl restart postfix
```

Then run the ingest worker and forward a message to the address the dashboard
shows you under forwarding setup.
