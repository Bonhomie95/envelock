# Customer-facing content and plan delivery review

## Decision

The three advertised plans have implemented feature boundaries and matching base-price calculations. This is not yet a blanket confirmation that every advertised feature is operational in a live deployment. External-service configuration, provider consent, connectivity, and real payment/webhook acceptance testing remain necessary. No live billing transactions, provider authorizations, production changes, or pushes were made.

| Plan | Customer promise | Code and test evidence | Delivery qualification |
| --- | --- | --- | --- |
| Guard / Free | Domain and lookalike monitoring; no connected mailbox protection | External-domain detections and scheduled watchers exist; Guard has zero mailbox seats. This review explicitly restricts Guard to domain detections and prevents a saved payment method from granting mailbox entitlement. | The inspected local server configuration enables scheduled jobs and the domain watcher, with focus-core mode off. Actual deployed watcher health, DNS access, and notifications are not proved by these flags. |
| Essential | $25/month for one domain and five mailboxes; payment-fraud alerts, supplier workflow, AI review of suspicious payment mail | Price calculation is $15 + five $2 mailboxes; paid/trial entitlement and payment-focused AI gates are implemented. Pipeline, AI, supplier, billing, and entitlement tests exercise these paths. | Requires a connected mailbox and an operational AI provider. AI review has a monthly usage allowance (the inspected configuration is 200 calls per mailbox). The preview intentionally has AI disabled. |
| Complete | $49/month for one domain and five mailboxes; Essential plus phishing AI review, identity alerts, automatic quarantine | Price calculation is $31.50 + five $3.50 mailboxes. Complete gates identity detections, phishing AI review, and automatic remediation. Tests include a local IMAP socket workflow. | Identity coverage requires supported logs or sensors. Automatic quarantine requires write permissions and a supported connection; forwarding is alert-only. Live provider behavior remains unverified. |
| Additional mailboxes | Essential $2/month each; Complete $3.50/month each | Constants, subscription updates, seat enforcement, and payment-failure handling are implemented and tested. | **Not ready in the inspected local server configuration:** both extra-mailbox Stripe Price IDs are absent. Configure matching Stripe prices and verify checkout, seat changes, invoices, and webhooks before offering this path as ready. |

The local server configuration also has AI/provider credentials and base Stripe price IDs present. Presence does not establish credential validity, OAuth approval, actual Stripe price amounts, production deployment state, or reliable end-to-end service. Only configuration booleans were inspected; secret values were not displayed. The running preview uses a separate database and explicit local-only configuration.

## Changes delivered

- Trimmed landing-page AI explanations into connection, warning review, and response guidance. Removed detector sequencing, internal escalation rules, and trigger descriptions.
- Simplified the lab, billing, alert details, and privacy/subprocessor copy. Kept actionable evidence, privacy disclosures, procurement limits, and connection requirements.
- Removed internal model/cost/token/transition details from customer AI-verdict responses. Customer status responses retain connection availability and AI usage information, without platform metrics or internal costs.
- The detection lab now withholds scores, detector identifiers, and raw diagnostic evidence for both anonymous and signed-in customers. Outcomes and practical next actions remain available.
- Restricted the raw detector catalogue to authorized staff and disabled generated API schema publication in production. Runtime customer APIs remain usable; this is data minimization, not a claim that browser-delivered software cannot be inspected or copied.
- Reused one paid-plan description source across the landing page and billing/upgrade views, reducing conflicting promises.
- Replaced unconditional “stops fraud,” full-protection, and automatic-removal language with accurate detection and connection-dependent descriptions. Disclosed AI usage limits.
- Tightened Guard entitlement and registry checks. Updated paid-feature test fixtures to use paid accounts; added explicit Free-plan regression coverage.
- Fixed cross-origin PUT support required by billing seat changes.
- Prevented subscription plan changes from retaining an old extra-seat price when the destination plan’s price is missing. Failure leaves the subscription unchanged.
- Corrected an empty activity list that previously claimed a mailbox was connected and monitoring without supporting evidence.

## Validation

- Full backend regression run after the entitlement/billing changes: 880 passed, 1 skipped (missing PRD.md), 22 existing deprecation warnings.
- Updated paid-pipeline/corpus/security fixtures: 36 passed, 1 skipped.
- Customer-surface and AI explanation checks: 15 passed.
- Focused plan, billing, API, and AI checks with database row-level security enforced: 37 passed.
- Final lab-redaction and production-schema checks: 28 passed.
- Frontend: 29 passed; production build and ESLint passed.
- Backend Ruff passed; typecheck reports no new errors against the existing 33-error baseline.

The operator console and private engineering documents retain implementation detail needed to operate and maintain the service. They are not customer documentation. Existing authenticated coverage/support identifiers and useful incident evidence were not removed merely because they are technical.

## Required before claiming complete live delivery

1. Configure and validate Stripe prices for additional mailboxes, including the correct currency and recurring amount.
2. Run real provider-consent, message-delivery, alert, and quarantine acceptance tests for the offered connection types.
3. Verify the deployed AI provider, usage allowance, and failure behavior with approved synthetic messages.
4. Confirm live domain-watcher health and notification delivery for Free customers, including after a paid trial expires.
5. Verify base/extra-seat checkout, subscription changes, payment failures, cancellation, and webhook processing with Stripe test-mode transactions before live billing.

These requirements are operational verification gaps, not assurances that the product is vulnerability-free or that all real-world attacks will be detected.
