# IOC Extract - `samples/case02_invoice_attachment.eml`

| Field | Value |
|---|---|
| From | `Pinecrest Supply Accounts <accounts@pinecrest-supply.example>` |
| Reply-To | `pinecrest.billing.dept@quickmail-free.example` |
| Return-Path | `<accounts@pinecrest-supply.example>` |
| To | `ap-team@ridgeline.example` |
| Subject | `Overdue invoice #88213 - final notice` |
| Date | `Tue, 15 Sep 2026 14:03:10 -0400` |
| Message-ID | `<CAF88213.9921@pinecrest-supply.example>` |
| SPF / DKIM / DMARC | softfail / fail / fail |
| Origin IP | `198.51.100.23` |

## URLs (defanged)

- `(none)`

## Attachments

- `Invoice_88213.html` SHA256 `e8eae359f834670a5a486e3a19588ae2d5870a9e6966f839cc19ac11748a9633`

## Red Flags

- (+1) SPF result is 'softfail'
- (+1) DKIM result is 'fail'
- (+1) DMARC result is 'fail'
- (+1) Reply-To domain (quickmail-free.example) differs from From domain (pinecrest-supply.example)
- (+1) Free-mail domain used in From/Reply-To: quickmail-free.example
- (+2) Risky attachment type: Invoice_88213.html
- (+1) Urgency / pressure language: immediately, final notice, overdue

**Automated triage:** LIKELY MALICIOUS (score 8)

> Automated output is a starting point. Analyst must confirm with threat intel + context.
