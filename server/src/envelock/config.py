"""Configuration, loaded from environment / .env.

Mirrors .env.example one-for-one. Optional providers default to unset: a missing
provider disables the detections that depend on it and downgrades the mailbox's
protection level (PRD P4) rather than failing at runtime or silently pretending
coverage exists.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ENVELOCK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    env: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"
    api_host: str = "0.0.0.0"  # noqa: S104
    api_port: int = 8010
    #: Trust the client IP in `X-Forwarded-For`. Enable ONLY when the app sits
    #: behind a proxy you control (nginx, a load balancer, Cloudflare) — otherwise
    #: every client shares the proxy's single IP and rate limits apply globally.
    #: Off by default because a spoofable header would otherwise bypass throttling.
    trust_forwarded_for: bool = False

    secret_key: SecretStr = SecretStr("")

    #: Bearer token a Prometheus scraper presents at `/metrics`. Unset means the
    #: endpoint answers only local/private peers (nginx on the same box, a
    #: scraper in the same VPC). Set it when the scraper is genuinely remote.
    metrics_token: SecretStr | None = None

    #: Emit one JSON object per log line. On in production, where logs are shipped
    #: and queried; off in development, where a person reads them directly.
    log_json: bool | None = None

    # ── Credential key custody (PRD §5.2) ────────────────────────────────────
    # We store hundreds of businesses' mailbox passwords. Which provider wraps the
    # per-secret data key — and, critically, whether THIS process can unwrap it —
    # is the difference between "a compromised web pod leaks one request" and "a
    # compromised web pod leaks every credential we hold". See security/keys.py.
    #
    #   local   — AES-GCM under credential_master_key. Development only.
    #   x25519  — public-key wrapping; the API gets only the public half.
    #             Recommended for self-hosted production.
    #   aws     — AWS KMS Encrypt/Decrypt, split by IAM.
    #   gcp     — Cloud KMS encrypt/decrypt, split by IAM.
    #   auto    — infer from whichever key material is set (the default).
    credential_key_provider: Literal["auto", "local", "x25519", "aws", "gcp"] = "auto"

    credential_master_key: SecretStr = SecretStr("")

    #: base64 X25519 public key. Set this ALONE on the API to make it structurally
    #: incapable of reading the credential store. Generate a pair with
    #: `python -m envelock.security.keygen`.
    credential_public_key: str | None = None
    #: base64 X25519 private key. Set ONLY on the worker/broker deployment.
    credential_private_key: SecretStr | None = None

    kms_key_id: str | None = None
    kms_provider: Literal["aws", "gcp"] | None = None
    kms_region: str | None = None
    #: Declares that this process's IAM role is granted Decrypt. It is a statement
    #: about the deployment, not something we can probe — an API pod should leave
    #: it false so an attempt to decrypt fails loudly here rather than succeeding
    #: because someone over-granted the role.
    credential_can_decrypt: bool = True

    # ── Datastores ───────────────────────────────────────────────────────────
    postgres_dsn: str = "postgresql+asyncpg://envelock:envelock@localhost:5432/envelock"
    #: Disable connection pooling — set only for the test suite, where many short
    #: event loops would otherwise reuse a connection across loops. Production
    #: keeps pooling for performance.
    db_nullpool: bool = False
    #: Pooled connections per process, and how many more it may open under load.
    #: SQLAlchemy's default (5 + 10) is below what a concurrent poll cycle, the
    #: scheduler and live requests need together.
    db_pool_size: int = 10
    db_max_overflow: int = 10
    redis_dsn: str = "redis://localhost:6379/0"
    #: "memory" (single instance) or "redis" (shared across instances, PRD §17.3).
    rate_limit_backend: Literal["memory", "redis"] = "memory"
    clickhouse_dsn: str = "clickhouse://envelock:envelock@localhost:8123/envelock"
    kafka_bootstrap: str = "localhost:19092"
    kafka_topic_events: str = "envelock.events"

    # ── Channel 1: Tier 1 ────────────────────────────────────────────────────
    ms_client_id: str | None = None
    ms_client_secret: SecretStr | None = None
    ms_redirect_uri: str | None = None
    ms_webhook_url: str | None = None

    #: Shared secret a provider must present on the push endpoints. Graph carries
    #: it in the subscription's signed `clientState`; Gmail Pub/Sub appends it to
    #: the push URL as `?token=`. Without it those endpoints are unauthenticated
    #: cross-tenant triggers, so an unset secret means "reject every push" in
    #: production. Defaults to the app secret key when unset.
    webhook_shared_secret: SecretStr | None = None

    google_client_id: str | None = None
    google_client_secret: SecretStr | None = None
    google_redirect_uri: str | None = None
    google_pubsub_topic: str | None = None

    # ── Channel 1: Tier 3 IMAP broker (PRD §5.3, §12.11D) ────────────────────
    imap_idle_enabled: bool = True
    imap_monitored_poll_seconds: int = 900
    imap_max_connections_per_egress_ip: int = 15
    """MEASURE this per provider before launch — it is the dominant Tier 3 cost
    driver and it is set by provider policy, not by our efficiency."""

    imap_idle_refresh_seconds: int = 1500
    imap_reconnect_jitter_seconds: int = 120
    imap_egress_ips: str = ""

    #: The live IMAP poll worker (workers/imap_fetch). On by default so a
    #: connected mailbox is actually read; the poll cadence is the protection
    #: latency for Monitored mailboxes and the fallback for Protected ones.
    #: Disabled in the test suite, which drives the worker directly.
    imap_poll_worker_enabled: bool = True
    imap_poll_worker_seconds: int = 60
    #: How many mailboxes one poll cycle checks at the same time. Each in-flight
    #: poll holds a database connection and a worker thread while it waits on
    #: the mail server, so this must stay below the pool (`db_pool_size` +
    #: `db_max_overflow`), leaving room for the scheduler and API work.
    imap_poll_concurrency: int = 8

    #: Allow an IMAP connection to a loopback/private/link-local address. OFF by
    #: default: the host comes straight from a customer form, so without this
    #: guard "test connection" is a blind port scanner pointed at our own
    #: infrastructure (including the cloud metadata endpoint). Turn it on only
    #: for a self-hosted deployment whose mail server really is on the LAN.
    imap_allow_private_hosts: bool = False

    #: Allow an IMAP session with NO transport encryption at all. OFF by default.
    #: `security="none"` skipped both the implicit-TLS and the STARTTLS branch and
    #: went straight to `client.login()`, putting the customer's mailbox password
    #: on the wire in cleartext on the connect AND on every subsequent poll — from
    #: the product whose stated purpose is preventing exactly that interception.
    #: The STARTTLS path next to it already refuses to degrade, with a comment
    #: saying why; this closes the same hole on the third mode. Turn it on only
    #: for a self-hosted deployment reaching a mail server over a trusted LAN.
    imap_allow_plaintext: bool = False

    #: Extra ports the IMAP connector may dial, beyond 143/993/1143/2143 —
    #: comma-separated. Restricting ports is what stops the connect form being
    #: used as a general port scanner, so widen this deliberately.
    imap_extra_allowed_ports: str = ""

    #: Per-candidate connect+login budget while probing IMAP settings. The whole
    #: ladder has to fit inside a request the customer is watching.
    imap_probe_timeout_seconds: float = 8.0
    #: How many discovered candidates one probe may dial.
    imap_probe_max_candidates: int = 8

    # ── Channel 1: Tier 4 ────────────────────────────────────────────────────
    ingest_domain: str = "in.envelock.org"
    ingest_smtp_host: str = "0.0.0.0"  # noqa: S104
    ingest_smtp_port: int = 2525
    #: Start the forwarding SMTP listener inside the API process so Tier-4
    #: forwarding works without deploying a separate process. Off by default and
    #: in tests; a dedicated MX host is still the production-scale option.
    ingest_smtp_in_app: bool = False

    # ── Channel 2 ────────────────────────────────────────────────────────────
    vapid_public_key: str | None = None
    vapid_private_key: SecretStr | None = None
    vapid_subject: str = "mailto:security@envelock.org"

    ipinfo_token: SecretStr | None = None
    ipqs_api_key: SecretStr | None = None

    # ── Channel 3 (free-first) ───────────────────────────────────────────────
    certstream_url: str = "wss://certstream.calidog.io/"
    czds_username: str | None = None
    czds_password: SecretStr | None = None
    rdap_bootstrap_url: str = "https://rdap.org/"
    nrd_feed_api_key: SecretStr | None = None
    #: Enrich /domains/scan hits with RDAP registration dates (and sort by them).
    #: On in production; the suite turns it off so scans stay hermetic.
    scan_registration_dates: bool = True

    # ── Focus mode: the two launch features ──────────────────────────────────
    #: Ship only the two v1 features — (1) link safety, (2) payment safety —
    #: plus the surface they need (auth, domains, mailbox connect, alerts,
    #: notifications). When true, the staff/admin/security-posture routers are
    #: not mounted (the operator console 404s) and the CT-log watcher does not
    #: start. Billing and governance stay mounted (main.py explains why), and
    #: the SIEM webhook drain always runs — alerts enqueue deliveries
    #: unconditionally, so parking the drain silently broke every registered
    #: endpoint. Flip to false to light the operator console back up.
    focus_core: bool = True

    # ── Feature 1: link safety (PRD §7 of the clean-slate plan) ──────────────
    safebrowsing_api_key: SecretStr | None = None
    urlhaus_enabled: bool = True
    #: Rewrite every URL in a protected mailbox's inbound mail to the click-time
    #: redirector (`/r/{token}`), by writing a modified copy back over IMAP.
    #: This is what makes protection device-agnostic: the phone tapping the link
    #: has no extension installed, but the link itself now routes through us.
    link_rewrite_enabled: bool = True
    #: Inject the warning banner into the body of a flagged message (write-back).
    banner_enabled: bool = True
    #: Public origin of the click-time redirector, used to build rewritten links.
    #: Must be reachable from the recipient's device. Empty = this API's own
    #: local origin (dev). Production: a short dedicated domain or the API host.
    redirect_base_url: str = ""
    #: How many URLs per message get live reputation checks at delivery time
    #: (each is one cached Safe Browsing lookup when a key is configured).
    url_check_max_per_message: int = 5

    # ── AI cascade (last rung — LLM BEC-intent judge, PRD §12.11 §12.12) ─────
    #: Provider for the LLM judge: "none" (off, default), "anthropic", "openai",
    #: or "local" (any OpenAI-compatible endpoint — Ollama, vLLM, llama.cpp).
    #: The judge only runs on the small fraction of mail the rules already flag as
    #: ambiguous/risky (the cascade gate), and is capped per mailbox, so cost stays
    #: near-zero. It can confirm or escalate a verdict, never silently suppress one.
    llm_provider: Literal["none", "anthropic", "openai", "local"] = "none"
    #: Hard monthly cap on judge calls per mailbox (COGS guardrail).
    llm_max_calls_per_mailbox_month: int = 200
    #: Confidence (0-1) the judge must reach before it acts on a verdict.
    llm_min_confidence: float = 0.75
    llm_timeout_seconds: float = 20.0

    # Anthropic — cheap, fast Haiku is the right last-rung triage default; raise to
    # a larger model only if the fall-through data justifies it (§12.12D).
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-haiku-4-5"
    anthropic_base_url: str = "https://api.anthropic.com"

    # OpenAI (also the shape used by "local"). gpt-4o-mini is the cost default.
    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"

    # Local / self-hosted OpenAI-compatible server (Ollama default port shown).
    local_llm_base_url: str = "http://localhost:11434/v1"
    local_llm_model: str = "llama3.1"
    local_llm_api_key: SecretStr | None = None

    clamav_host: str = "localhost"
    clamav_port: int = 3310
    yara_rules_path: str = "./rules/yara"
    attachment_cache_ttl_clean_days: int = 14
    detonation_enabled: bool = False
    virustotal_api_key: SecretStr | None = None
    detonation_provider: str | None = None
    detonation_monthly_cap_per_mailbox: int = 150

    # ── Notifications (PRD §8.1) ─────────────────────────────────────────────
    #: Unset by default (like every other provider): L2 email is disabled until a
    #: real SMTP host is configured, rather than silently failing against
    #: localhost. L0 in-app always covers the alert regardless.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str = "alerts@envelock.org"
    smtp_dkim_private_key_path: str | None = None
    smtp_dkim_selector: str = "envelock"
    smtp_relay_fallback_dsn: str | None = None

    sms_enabled: bool = False
    sms_provider: str | None = None
    sms_api_key: SecretStr | None = None
    sms_sender_id: str = "Envelock"
    #: Provider REST endpoint for SMS. Twilio-style form POST by default; any
    #: provider that accepts an HTTP form/JSON body works via sms_provider.
    sms_api_url: str | None = None
    sms_account_sid: str | None = None  # Twilio account SID (basic-auth user)
    escalate_critical_after_seconds: int = 900
    escalate_unacked_count: int = 5

    # ── Background scheduler (PRD §8.1 E6, §15.2 retention, §17 watchers) ─────
    #: The in-process periodic scheduler that runs everything that must fire on a
    #: timer: E6 escalation, retention purge, OAuth token refresh, and the
    #: Channel-3 domain watchers. Disabled in the test suite (which drives each
    #: job directly); on by default so the product actually *does* things.
    scheduler_enabled: bool = True
    escalation_cycle_seconds: int = 60
    retention_purge_seconds: int = 3600
    oauth_refresh_seconds: int = 1800
    #: How often to re-check that verified domains still have their DNS proof, and
    #: revoke verification if the record was deleted (so access re-gates on the
    #: verify step). Hourly — deletion is rare and revocation is high-impact.
    domain_reverify_seconds: int = 3600
    #: How often the monthly-digest job WAKES UP, not how often a customer gets
    #: one — the due date lives on the tenant row, so this only decides how
    #: promptly a due digest goes out. Six-hourly: a digest arriving a few hours
    #: after its due moment costs nothing, and a tight loop here would mean
    #: scanning every tenant a hundred times a day to send nothing.
    digest_cycle_seconds: int = 21_600
    #: How often the outbound SIEM webhook queue is drained. Short: a customer's
    #: SIEM should see an alert while it still matters. The retry schedule
    #: (governance/export.RETRY_SCHEDULE) covers a receiver that is down.
    webhook_delivery_seconds: int = 30
    #: Channel-3 CT-log watcher (certstream). The free Guard tier and the S12
    #: pre-signup demo depend on this running.
    ct_watcher_enabled: bool = True
    #: How often the watcher reloads the set of protected domains from the DB.
    watcher_domain_refresh_seconds: int = 300

    # ── Tenant isolation (PRD §11, §15) ──────────────────────────────────────
    #: Enforce Postgres row-level security by connecting through the restricted
    #: `envelock_app` role and setting the per-request tenant GUC. Off by default
    #: because it requires the RLS migration + role to be provisioned first; when
    #: on, every session sets `envelock.tenant_id` so the DB backstops isolation
    #: even if an application query forgets its `WHERE tenant_id`.
    rls_enabled: bool = False

    #: Escape hatch for the production boot check that now REQUIRES `rls_enabled`.
    #: Deliberately awkward and deliberately named: a deployment that turns this
    #: on has chosen to run its multi-tenant mail store without the database-level
    #: isolation backstop, and that choice should be visible in the environment
    #: file rather than implied by a default.
    allow_rls_disabled: bool = False

    #: The Postgres role the application connects as when RLS is on. It must not
    #: be a superuser and must not hold BYPASSRLS — Postgres ignores every policy
    #: for those, FORCE included, so the app would connect happily and be
    #: completely unprotected. `verify_rls` checks this at boot and the admin
    #: security page reports it. `python -m envelock.security.provision_rls`
    #: creates the role correctly.
    db_app_role: str = "envelock_app"

    #: DSN with DDL rights — the table OWNER, not the restricted request-path
    #: role. Used by Alembic and by the boot-time RLS application, and by nothing
    #: that serves a request.
    #:
    #: Without this the two jobs collide. `provision_rls` deliberately grants the
    #: app role only SELECT/INSERT/UPDATE/DELETE, so once `postgres_dsn` points at
    #: it: `alembic upgrade head` fails on every deploy, and `apply_rls` at boot
    #: cannot create a policy or grant on a newly added table — it logs an error
    #: and carries on, leaving a deployment that believes it has row-level
    #: security and does not.
    #:
    #: Unset means "same as postgres_dsn", which is correct in development where
    #: the app connects as the owner anyway.
    db_owner_dsn: str | None = None

    #: Require DNS domain-control verification before a mailbox on that domain can
    #: be connected for live mail. On by default so nobody can sign up with a
    #: company address they do not control and receive that company's alerts.
    require_domain_verification: bool = True

    #: At registration, reject an email whose domain doesn't resolve in DNS (no MX
    #: and no A/AAAA) — catches typos/made-up domains like test@hjsbcjsjs.com
    #: before ownership verification. Fails open on a transient DNS failure.
    check_email_domain_exists: bool = True

    # ── Sender-domain reputation (free feeds — user requirement #3) ──────────
    #: DNSBL zones queried for the FROM domain's registrable domain. All free and
    #: DNS-based (no API key). Spamhaus DBL is free for low-volume/non-commercial
    #: — audit terms before high volume (README licensing note).
    domain_reputation_enabled: bool = True
    dnsbl_domain_zones: str = "dbl.spamhaus.org,multi.surbl.org"
    reputation_cache_seconds: int = 3600

    # ── Tier-4 forwarding ingest authentication (PRD §5.4 / security) ────────
    #: Comma-separated CIDR/IP allowlist of forwarders permitted to submit to the
    #: SMTP/HTTP ingest. Empty = allow any (dev only). A per-tenant token in the
    #: RCPT address is necessary but not sufficient; pin the source too.
    ingest_allowed_ips: str = ""

    #: Allow tenant-configured SIEM webhook URLs to resolve to private/reserved
    #: addresses. Off by default — that shape is SSRF. Turn on only for a
    #: self-hosted deployment whose SIEM lives on the same private network.
    webhook_allow_private_hosts: bool = False

    #: Require proof of email ownership before an account can sign in. This is
    #: the anti-squatting control for one-company-one-tenant: without it, anyone
    #: can register a fake address on a company's domain, permanently claim that
    #: domain's tenant (and burn its one trial), and have the company's real
    #: employees auto-join *the attacker's* workspace as pending members. Off by
    #: default (dev/tests, and relay-less deployments); turn on in production as
    #: soon as outbound mail works. While on, unverified corporate tenants are
    #: skipped by the colleague auto-join and the trial only starts at
    #: verification.
    #:
    #: Still `False` by default so a laptop with no relay can sign up, but
    #: production now refuses to boot with it off unless
    #: `allow_unverified_signups` is set — see `_check_production_secrets`.
    require_email_verification: bool = False

    #: Escape hatch for the production boot check that REQUIRES
    #: `require_email_verification`. Named the way it is so the environment file
    #: says out loud what has been accepted: anyone may claim any company's
    #: domain on this deployment.
    allow_unverified_signups: bool = False

    # ── Billing (PRD §12) ────────────────────────────────────────────────────
    trial_days: int = 15
    trial_backfill_days: int = 30
    backfill_days: int = 90
    #: Max messages a single backfill sweep will pull per mailbox. Generous so
    #: onboarding can scan the whole recent history, bounded so a pathologically
    #: huge mailbox can't stall a worker. A "scan everything" backfill uses this.
    backfill_max_messages: int = 5000

    # Public origin of the web app, used to build Stripe Checkout return URLs
    # (success/cancel). Server-built rather than client-supplied so a caller can't
    # turn checkout into an open redirect. Defaults to the local dev origin.
    public_base_url: str = "http://localhost:5173"

    # Global payment rails. Stripe is the primary processor (North America and
    # global); the regional acquirers cover markets Stripe serves less well.
    stripe_secret_key: SecretStr | None = None
    stripe_webhook_secret: SecretStr | None = None
    # Stripe Price IDs (recurring, monthly) for each paid plan. Created once in the
    # Stripe dashboard; the checkout session references them so pricing lives in
    # Stripe, not hardcoded in a charge call.
    stripe_price_essential: str | None = None
    stripe_price_complete: str | None = None
    adyen_api_key: SecretStr | None = None  # Europe / global enterprise
    adyen_merchant_account: str | None = None
    mercadopago_access_token: SecretStr | None = None  # Latin America
    razorpay_key_id: str | None = None  # Asia (India and neighbours)
    razorpay_key_secret: SecretStr | None = None
    paypal_client_id: str | None = None
    paypal_client_secret: SecretStr | None = None

    # Platform operators who can reach the cross-tenant admin console. A simple
    # allowlist (comma-separated emails) rather than a self-service flag — super
    # admin can never be granted through the product itself, only by deployment.
    superadmin_emails: str = ""

    # Browser origins allowed to call the API cross-origin (comma-separated). The
    # web client is served from a different origin than the API in production
    # (e.g. Vercel → Render), so its origin must be allow-listed or the browser
    # blocks every call. Localhost dev origins are always allowed.
    cors_origins: str = "https://app.envelock.org,https://admin.envelock.org"

    # Public URL of the web client — used to build links in outbound email (e.g.
    # the password-reset link). MUST match the deployed client origin: a wrong
    # value here does not fail loudly, it emails every customer a reset link
    # pointing at a host that is not yours.
    web_base_url: str = "https://app.envelock.org"

    # DANGER — one-time schema rebuild. When true, the app DROPS AND RECREATES the
    # database schema on startup (wiping all data), to repair a drifted pre-launch
    # database. Set true, redeploy once, then set back to false. Never true with
    # real customer data — use Alembic migrations instead.
    reset_schema_on_startup: bool = False

    # ── Derived ──────────────────────────────────────────────────────────────
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def ddl_dsn(self) -> str:
        """The DSN to run schema changes with. Falls back to the app's own."""
        return self.db_owner_dsn or self.postgres_dsn

    @property
    def redirect_base(self) -> str:
        """Origin the rewritten links point at, without a trailing slash."""
        base = self.redirect_base_url.strip().rstrip("/")
        return base or f"http://localhost:{self.api_port}"

    @property
    def superadmin_email_set(self) -> frozenset[str]:
        return frozenset(
            e.strip().lower() for e in self.superadmin_emails.split(",") if e.strip()
        )

    @property
    def cors_origin_list(self) -> list[str]:
        """Configured cross-origin callers, plus the local dev origins off-prod.

        The dev origins used to be appended unconditionally. Combined with
        `allow_credentials=True` in `main.py`, that meant production trusted
        `http://localhost:5173` — an origin any process on a customer's machine
        can claim by binding a port. A malicious local dev server, browser
        extension or npm postinstall script could then make credentialed
        cross-origin calls to the live API with the signed-in user's session.
        """
        configured = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        dev = (
            []
            if self.is_production
            else ["http://localhost:5173", "http://localhost:5174"]
        )
        # De-dupe while preserving order.
        return list(dict.fromkeys(configured + dev))

    @property
    def egress_ip_pool(self) -> list[str]:
        return [ip.strip() for ip in self.imap_egress_ips.split(",") if ip.strip()]

    @property
    def imap_extra_port_set(self) -> frozenset[int]:
        ports: set[int] = set()
        for raw in self.imap_extra_allowed_ports.split(","):
            token = raw.strip()
            if token.isdigit() and 1 <= int(token) <= 65535:
                ports.add(int(token))
        return frozenset(ports)

    @property
    def dnsbl_domain_zone_list(self) -> list[str]:
        return [z.strip() for z in self.dnsbl_domain_zones.split(",") if z.strip()]

    @property
    def ingest_allowed_ip_list(self) -> list[str]:
        return [ip.strip() for ip in self.ingest_allowed_ips.split(",") if ip.strip()]

    @field_validator(
        "kms_provider",
        "log_json",
        "credential_public_key",
        "credential_private_key",
        "kms_key_id",
        mode="before",
    )
    @classmethod
    def _empty_env_is_none(cls, v):  # noqa: ANN001, ANN206
        """An empty environment variable means "not set" for optional enums.

        Env vars outrank the .env file, so tests (and deployments) blank a key
        with `VAR=""` — which pydantic otherwise rejects for Literal/bool
        options with a confusing validation error at boot."""
        if v == "":
            return None
        return v

    @model_validator(mode="after")
    def _reject_leaked_comments(self) -> Settings:
        """Catch `.env` lines where an example comment became the value.

        python-dotenv does not strip a trailing `# comment` from an unquoted
        value, so `KEY=   # explains the key` loads the comment text as the
        setting. That silently "configures" a provider with nonsense — a KMS key
        id, an API key — and fails much later at call time. Fail at boot instead.
        """
        bad: list[str] = []
        for name in type(self).model_fields:
            raw = getattr(self, name, None)
            value = (
                raw.get_secret_value() if hasattr(raw, "get_secret_value") else raw
            )
            if isinstance(value, str) and value.lstrip().startswith("#"):
                bad.append(f"ENVELOCK_{name.upper()}")
        if bad:
            raise ValueError(
                "These .env values are example comments, not real values — the "
                "comment must go on its own line above the key: "
                + ", ".join(sorted(bad))
            )
        return self

    @model_validator(mode="after")
    def _check_production_secrets(self) -> Settings:
        """Fail loudly at boot rather than quietly in production.

        A missing credential master key would mean tenant mail passwords stored
        without envelope encryption — that must never start.
        """
        # Staging is internet-facing too. With an empty SECRET_KEY every session
        # token is HMAC'd with b"" — forgeable offline by anyone, for any user,
        # any tenant, any role. Only local development may run without one.
        if self.env == "staging" and not self.secret_key.get_secret_value():
            raise ValueError(
                "Refusing to start in staging without ENVELOCK_SECRET_KEY — "
                "session tokens would be signed with an empty key and trivially "
                "forgeable."
            )
        if self.env != "production":
            return self

        missing: list[str] = []
        if not self.secret_key.get_secret_value():
            missing.append("ENVELOCK_SECRET_KEY")
        if missing:
            raise ValueError(
                f"Refusing to start in production without: {', '.join(missing)}"
            )

        # Prove the credential key provider can actually be built. The previous
        # check accepted ENVELOCK_KMS_KEY_ID on its own as satisfying the
        # requirement, and then the sealing path raised at the first mailbox
        # connect because no master key was set — a production deployment that
        # started cleanly and could not store a single credential.
        from envelock.security.keys import KeyProviderError, build_provider

        try:
            # `self`, not get_settings(): this validator runs inside the Settings
            # constructor, so asking for the cached settings here would re-enter
            # it and recurse until the stack blows.
            build_provider(self)
        except KeyProviderError as exc:
            raise ValueError(
                f"Refusing to start in production: credential key custody is not "
                f"usable — {exc}"
            ) from exc

        # A one-time repair flag is a data-destruction switch. Left set on a box
        # with customers on it, every restart silently erases the product. It has
        # no legitimate production use, so production refuses to start with it on
        # rather than trusting someone to remember to unset it.
        if self.reset_schema_on_startup:
            raise ValueError(
                "Refusing to start in production with "
                "ENVELOCK_RESET_SCHEMA_ON_STARTUP=true — that flag DROPS THE "
                "SCHEMA AND ERASES ALL CUSTOMER DATA on every boot. Unset it. "
                "Schema changes in production go through `alembic upgrade head`."
            )

        # Tenant isolation is the whole promise of a multi-tenant mail product.
        # The RLS policies are written, applied at boot and covered by CI — but
        # `rls_enabled` defaulted to false, so the database backstop that catches
        # a query missing its `WHERE tenant_id` was not protecting the one
        # deployment that matters. Production must opt IN to running without it,
        # rather than opting in to having it.
        if not self.rls_enabled and not self.allow_rls_disabled:
            raise ValueError(
                "Refusing to start in production with ENVELOCK_RLS_ENABLED=false. "
                "Row-level security is the database backstop for tenant "
                "isolation. Provision it once with:\n"
                "    python -m envelock.security.provision_rls\n"
                "then set ENVELOCK_RLS_ENABLED=true and "
                "ENVELOCK_DB_APP_ROLE=envelock_app.\n"
                "If you have genuinely accepted the risk of running without it, "
                "set ENVELOCK_ALLOW_RLS_DISABLED=true — and write down why."
            )

        # One company, one tenant, one trial — and the whole thing rests on the
        # registrant proving they can read mail at the address they claimed.
        # Without this, registering `finance@theircompany.com` is enough to take
        # permanent ownership of that domain's workspace, burn its only trial,
        # and have the company's real staff auto-join the squatter's tenant as
        # pending members. It is the cheapest attack against us that exists and
        # it needs no skill, so production opts OUT of it explicitly or not at
        # all.
        if not self.require_email_verification and not self.allow_unverified_signups:
            raise ValueError(
                "Refusing to start in production with "
                "ENVELOCK_REQUIRE_EMAIL_VERIFICATION=false. Anyone could then "
                "register a fake address on a customer's domain, claim that "
                "company's tenant permanently and burn its only trial. Set it "
                "to true (it needs a working SMTP relay — see "
                "ENVELOCK_SMTP_HOST). If you have genuinely accepted that risk, "
                "set ENVELOCK_ALLOW_UNVERIFIED_SIGNUPS=true — and write down why."
            )

        # Verification on with no relay is worse than either alone: every signup
        # completes registration, no mail is ever sent, and nobody can sign in.
        # The product looks broken to every new customer and the logs say only
        # "not_configured". Catch it at boot instead of in support.
        if self.require_email_verification:
            host = (self.smtp_host or "").strip()
            if not host or host == "localhost" or not self.smtp_from:
                raise ValueError(
                    "Refusing to start in production with "
                    "ENVELOCK_REQUIRE_EMAIL_VERIFICATION=true and no outbound "
                    "mail relay: every new signup would be sent a verification "
                    "link that is never delivered, and no new customer could "
                    "ever sign in. Set ENVELOCK_SMTP_HOST and ENVELOCK_SMTP_FROM."
                )

        # The forwarding ingest accepts mail addressed to a per-tenant token. The
        # token proves which tenant a copy is for; it does not prove the sender is
        # that tenant's real gateway. With no allowlist anyone who learns a token
        # can inject mail to poison detection or fabricate alerts, so the listener
        # does not run open in production.
        if self.ingest_smtp_in_app and not self.ingest_allowed_ip_list:
            raise ValueError(
                "Refusing to start in production with the forwarding SMTP ingest "
                "enabled and ENVELOCK_INGEST_ALLOWED_IPS empty — that accepts "
                "forwarded mail from any source on the internet. Pin your mail "
                "provider's egress ranges, or set ENVELOCK_INGEST_SMTP_IN_APP=false."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
