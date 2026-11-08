"""Provider adapters for Channel 1.

Consent, subscription and status only. Every source's raw mail goes through
`parser.parse_message`, so nothing downstream branches on which provider mail
came from (PRD §10). Adapters report `configured` honestly: an
unset credential disables that path and downgrades the mailbox's protection
level rather than failing at call time (PRD P4).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta

from envelock.config import get_settings
from envelock.core.enums import SourceMechanism


class MailProvider(ABC):
    source: SourceMechanism

    @property
    @abstractmethod
    def configured(self) -> bool:
        """Whether credentials exist. False disables the path visibly."""

    # NOTE deliberately no fetch()/quarantine() here. Four implementations of
    # each existed, every one a stub (`return []` / `return self.configured` —
    # a statement about credentials dressed as a statement about a message
    # being moved), and nothing ever called them. Real acquisition lives in
    # channels/mail/api_fetch.py and imap_sync.py; real quarantine in
    # workers/imap_fetch.py. This class is the consent/subscription/status
    # surface only.

    def status(self) -> dict:
        return {
            "source": self.source.value,
            "configured": self.configured,
            "reason": None if self.configured else "credentials not set",
        }


# ── Tier 1: Microsoft 365 ────────────────────────────────────────────────────
class GraphProvider(MailProvider):
    """Microsoft Graph. Needs an Entra app registration."""

    source = SourceMechanism.GRAPH_API
    # User-consentable only — AuditLog.Read.All / Directory.Read.All need org
    # admin consent and were dropped so a Microsoft mailbox connects with no
    # admin involvement (see channels/mail/oauth._Microsoft.scopes).
    SCOPES = (
        "Mail.ReadWrite",
        "MailboxSettings.Read",
    )
    AUTHORITY = "https://login.microsoftonline.com"
    GRAPH = "https://graph.microsoft.com/v1.0"

    def __init__(self) -> None:
        s = get_settings()
        self.client_id = s.ms_client_id
        self.client_secret = (
            s.ms_client_secret.get_secret_value() if s.ms_client_secret else None
        )
        self.redirect_uri = s.ms_redirect_uri
        self.webhook_url = s.ms_webhook_url

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def consent_url(self, *, state: str) -> str | None:
        if not self.configured:
            return None
        scope = "https://graph.microsoft.com/.default"
        return (
            f"{self.AUTHORITY}/organizations/v2.0/adminconsent"
            f"?client_id={self.client_id}&state={state}"
            f"&redirect_uri={self.redirect_uri}&scope={scope}"
        )

    def subscription_body(self, *, mailbox: str, tenant_id: object = "") -> dict:
        """Change notifications. Graph will not deliver to localhost, so the
        webhook URL must be public HTTPS.

        `clientState` carries an HMAC over the tenant and mailbox: Graph echoes
        it on every notification, so it is both the receiver's authentication and
        its authorisation to touch exactly this mailbox.
        """
        from envelock.security.webhook_auth import client_state

        return {
            "changeType": "created,updated",
            "notificationUrl": self.webhook_url,
            # Delegated token → me/..., never users/{label}: the stored label
            # (e.g. admin@cyberlex.store) is not the account's real UPN, so
            # users/{label} is "another user" and Graph denies it (403). me/
            # resolves to the token's own mailbox. Matches the fetch path.
            "resource": "me/mailFolders('inbox')/messages",
            "expirationDateTime": (datetime.now(UTC) + timedelta(days=2)).isoformat(),
            "clientState": client_state(tenant_id=tenant_id, mailbox=mailbox),
        }


# ── Tier 1: Google Workspace ─────────────────────────────────────────────────
class GmailProvider(MailProvider):
    source = SourceMechanism.GMAIL_API
    # Must match the scopes the live OAuth flow requests (channels/mail/oauth.py).
    # admin.reports.audit.readonly was dropped — we never used the audit log — and
    # requesting a scope you don't use is a guaranteed verification rejection.
    SCOPES = (
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.settings.basic",
    )

    def __init__(self) -> None:
        s = get_settings()
        self.client_id = s.google_client_id
        self.client_secret = (
            s.google_client_secret.get_secret_value()
            if s.google_client_secret
            else None
        )
        self.redirect_uri = s.google_redirect_uri
        self.pubsub_topic = s.google_pubsub_topic

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def consent_url(self, *, state: str) -> str | None:
        if not self.configured:
            return None
        return (
            "https://accounts.google.com/o/oauth2/v2/auth"
            f"?client_id={self.client_id}&redirect_uri={self.redirect_uri}"
            f"&response_type=code&access_type=offline&prompt=consent"
            f"&state={state}&scope={'%20'.join(self.SCOPES)}"
        )

    def watch_body(self) -> dict:
        return {"topicName": self.pubsub_topic, "labelIds": ["INBOX"]}

    @staticmethod
    def push_endpoint(base_url: str) -> str:
        """The Pub/Sub push URL to register, carrying the shared token Google
        echoes on every delivery — the receiver's only proof the call is ours."""
        from envelock.security.webhook_auth import push_token

        return f"{base_url.rstrip('/')}/api/v1/webhooks/gmail?token={push_token()}"


# ── Tier 3: IMAP ─────────────────────────────────────────────────────────────
class ImapProvider(MailProvider):
    """Works on any IMAP server. Credentials come from the encrypted store and
    are only ever decrypted inside the broker process (PRD §5.2)."""

    source = SourceMechanism.IMAP_IDLE

    def __init__(
        self,
        *,
        host: str,
        port: int = 993,
        username: str = "",
        password: str = "",
    ) -> None:
        self.host, self.port = host, port
        self._username, self._password = username, password

    @property
    def configured(self) -> bool:
        return bool(self.host and self._username and self._password)


# ── Tier 4: forwarding ───────────────────────────────────────────────────────
class ForwardingProvider(MailProvider):
    """The universal fallback: every mail system ever built supports forwarding.
    Post-delivery, so it can never quarantine."""

    source = SourceMechanism.FORWARD_INGEST

    @property
    def configured(self) -> bool:
        return True  # needs no credentials at all


def provider_status() -> list[dict]:
    """Which paths are usable right now, for the connect UI and diagnostics."""
    return [
        GraphProvider().status(),
        GmailProvider().status(),
        ForwardingProvider().status(),
        {
            "source": SourceMechanism.IMAP_IDLE.value,
            "configured": True,
            "reason": "per-mailbox credentials, no global configuration",
        },
    ]
