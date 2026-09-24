# IOC Extract - `samples/case01_credential_harvest.eml`

| Field | Value |
|---|---|
| From | `Ridgeline IT Service Desk <helpdesk@ridgeIine-support.example>` |
| Reply-To | `helpdesk@ridgeIine-support.example` |
| Return-Path | `<bounce-7731@mailer-cloudsend.example>` |
| To | `jsmith@ridgeline.example, apatel@ridgeline.example, mlee@ridgeline.example` |
| Subject | `ACTION REQUIRED: Your password expires in 24 hours` |
| Date | `Mon, 14 Sep 2026 08:12:44 -0400` |
| Message-ID | `<20260914121244.4471@mailer-cloudsend.example>` |
| SPF / DKIM / DMARC | fail / none / fail |
| Origin IP | `203.0.113.77` |

## URLs (defanged)

- `hxxps://portal[.]ridgeline[.]example/password-reset`
- `hxxps://ridgeline-sso-verify[.]example/auth/login?u=jsmith`

## Attachments

- (none)

## Red Flags

- (+1) SPF result is 'fail'
- (+1) DKIM result is 'none'
- (+1) DMARC result is 'fail'
- (+1) Return-Path domain (mailer-cloudsend.example) differs from From domain (ridgeiine-support.example)
- (+2) 1 link(s) where display text != real destination
- (+3) Sender domain 'ridgeiine-support.example' is a look-alike of protected domain 'ridgeline.example'
- (+2) URL domain 'ridgeline-sso-verify.example' uses our brand name but is not ours
- (+1) Urgency / pressure language: immediately, suspended, verify, within 24 hours, action required, password expires

**Automated triage:** LIKELY MALICIOUS (score 12)

> Automated output is a starting point. Analyst must confirm with threat intel + context.
