"""One branded HTML shell for every transactional email we send.

Why a shared module rather than HTML per call site: a customer's first contact
with us is the confirm-your-email message, and a bare text/plain mail from a
company selling *email* security reads as a phishing attempt — which is exactly
the instinct we spend the rest of the product training. One template, used
everywhere, so they all look like they came from the same company.

Two deliberate constraints:

* **The wordmark is text, not an image.** Outlook, Gmail and Apple Mail block
  remote images by default, so an image logo arrives as a broken-box icon on
  first open — worse than no logo. Styled text always renders.
* **Tables and inline styles.** Outlook renders through Word's HTML engine,
  which ignores most of `<style>`, flexbox and grid. This is ugly markup on
  purpose; anything more modern collapses into a single unstyled column there.

`send_mail` already takes `html_body` alongside the text `body`, and the text
part is never optional: it is what a terminal reader, a screen reader and every
HTML-stripping gateway shows.
"""

from __future__ import annotations

from html import escape

#: The product's light-theme tokens (client/src/index.css). The dark accent
#: (#ff5c1a) is only 3.1:1 on white — fine for a 100px headline in the app, not
#: for email body text, so the light-theme accent is used throughout here.
_ACCENT = "#c2410c"
_INK = "#0f141a"
_MUTED = "#52525b"
_RULE = "#e4e4e7"
_PAGE = "#f4f4f5"

_FONT = (
    "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif"
)


def _button(label: str, url: str) -> str:
    """A 'bulletproof' table button — the only kind Outlook renders as a button."""
    return f"""
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:28px 0;">
        <tr>
          <td align="center" bgcolor="{_ACCENT}" style="border-radius:4px;">
            <a href="{escape(url, quote=True)}"
               style="display:inline-block;padding:14px 28px;font-family:{_FONT};
                      font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;
                      border-radius:4px;">{escape(label)}</a>
          </td>
        </tr>
      </table>"""


def branded_email(
    *,
    heading: str,
    paragraphs: list[str],
    cta_label: str | None = None,
    cta_url: str | None = None,
    footnote: str | None = None,
    preheader: str | None = None,
) -> str:
    """Render one transactional email.

    `preheader` is the grey line an inbox shows next to the subject. Left unset,
    mail clients scrape the first words of the body instead, which for a message
    built around a button is usually the URL — so it is worth writing.
    """
    body_html = "".join(
        f'<p style="margin:0 0 14px;font-family:{_FONT};font-size:15px;'
        f'line-height:1.6;color:{_INK};">{escape(p)}</p>'
        for p in paragraphs
    )
    cta_html = _button(cta_label, cta_url) if cta_label and cta_url else ""
    # The raw URL, spelled out: a button that a client has stripped, or that the
    # reader simply does not trust, must still leave them a way through.
    fallback_html = (
        f'<p style="margin:0 0 8px;font-family:{_FONT};font-size:12px;'
        f'line-height:1.5;color:{_MUTED};">If the button does not work, paste this '
        f'into your browser:</p>'
        f'<p style="margin:0 0 20px;font-family:{_FONT};font-size:12px;'
        f'line-height:1.5;word-break:break-all;"><a href="{escape(cta_url, quote=True)}" '
        f'style="color:{_ACCENT};">{escape(cta_url)}</a></p>'
        if cta_url
        else ""
    )
    foot_html = (
        f'<p style="margin:0 0 20px;font-family:{_FONT};font-size:13px;'
        f'line-height:1.6;color:{_MUTED};">{escape(footnote)}</p>'
        if footnote
        else ""
    )
    pre_html = (
        f'<div style="display:none;max-height:0;overflow:hidden;opacity:0;">'
        f"{escape(preheader)}</div>"
        if preheader
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{_PAGE};">
{pre_html}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
       style="background:{_PAGE};padding:32px 12px;">
  <tr><td align="center">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
           style="max-width:560px;background:#ffffff;border:1px solid {_RULE};border-radius:6px;">
      <tr><td style="padding:28px 32px 0;">
        <span style="font-family:{_FONT};font-size:19px;font-weight:800;
                     letter-spacing:-0.02em;color:{_INK};">Envelock</span>
      </td></tr>
      <tr><td style="padding:20px 32px 0;">
        <h1 style="margin:0 0 16px;font-family:{_FONT};font-size:21px;font-weight:700;
                   line-height:1.3;color:{_INK};">{escape(heading)}</h1>
        {body_html}
        {cta_html}
        {fallback_html}
        {foot_html}
      </td></tr>
      <tr><td style="padding:0 32px;">
        <hr style="border:0;border-top:1px solid {_RULE};margin:0;"></td></tr>
      <tr><td style="padding:18px 32px 28px;">
        <p style="margin:0 0 6px;font-family:{_FONT};font-size:13px;color:{_INK};">
          &mdash; The Envelock team</p>
        <p style="margin:0;font-family:{_FONT};font-size:11px;line-height:1.6;color:{_MUTED};">
          Envelock stops your money going to the wrong bank account.<br>
          <a href="https://envelock.org" style="color:{_MUTED};">envelock.org</a>
          &nbsp;&middot;&nbsp; This is an automated message; replies are not monitored.
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""


__all__ = ["branded_email"]
