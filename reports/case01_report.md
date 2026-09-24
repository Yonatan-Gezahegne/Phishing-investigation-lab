# Incident Report: PHISH-2026-001 Credential Harvest Leading to Account Takeover

| Field | Value |
|---|---|
| **Case ID** | PHISH-2026-001 |
| **Analyst** | Yonatan Gezahegne |
| **Date reported** | 2026-09-14 |
| **Reported by** | mlee (recipient, did not interact) |
| **Classification** | Credential phishing → account compromise → internal BEC attempt |
| **Severity** | **Critical** |
| **Status** | Escalated to Tier 2 / IR, containment actions issued |

## 1. Executive Summary

A password-expiry phishing email from a look-alike domain (`ridgeIine-support[.]example`, with a capital "I" in place of "l") reached 3 employees. User **jsmith** entered credentials on a fake login page. About 40 minutes later, an attacker used that password from an external VPS, got in after jsmith approved an MFA push prompt, created a hidden inbox rule, searched the mailbox for payment terms, and sent an internal email to Accounts Payable about "updated banking details." This is a confirmed account takeover with an active payment-fraud attempt. Priority actions: lock the account, revoke its sessions, and tell AP not to act on that email.

## 2. Initial Evidence

- **Subject:** `ACTION REQUIRED: Your password expires in 24 hours`
- **Sender (display / address):** `Ridgeline IT Service Desk` / `helpdesk@ridgeIine-support[.]example`
- **Reply-To / Return-Path:** `helpdesk@ridgeIine-support[.]example` / `bounce-7731@mailer-cloudsend[.]example`
- **Recipients:** jsmith, apatel, mlee (@ridgeline.example)
- **SPF / DKIM / DMARC:** fail / none / fail
- **Originating IP / host:** `203.0.113[.]77` (`smtp07.mailer-cloudsend[.]example`, rDNS "unknown")
- **Delivery time:** 2026-09-14 08:12:47 -04:00

Key deception: the HTML link **displays** `https://portal.ridgeline.example/password-reset` (our real portal) but the **href** goes to `hxxps://ridgeline-sso-verify[.]example/auth/login?u=jsmith`. The `?u=` parameter is pre-filled per recipient, which suggests the campaign was targeted, not mass spam.

## 3. Indicators of Compromise (defanged)

| Type | Indicator | Context | TI Result |
|---|---|---|---|
| Domain | `ridgeIine-support[.]example` | Sender domain; homoglyph of `ridgeline.example` | Lab IOC (reserved TLD). In production: WHOIS age, VT |
| Domain | `ridgeline-sso-verify[.]example` | Credential-harvest page; uses our brand name | Lab IOC |
| URL | `hxxps://ridgeline-sso-verify[.]example/auth/login` | Phishing landing page | Lab IOC |
| URL | `hxxps://ridgeline-sso-verify[.]example/auth/submit` | Credential POST endpoint | Lab IOC |
| Domain | `mailer-cloudsend[.]example` | Sending infrastructure (Return-Path) | Lab IOC |
| IP | `203.0.113[.]77` | Email origin | Lab IOC |
| IP | `203.0.113[.]200` | Attacker sign-in source (VPS) | Lab IOC |
| User agent | `python-requests/2.31` | Scripted credential testing | n/a |
| Inbox rule | Name `.`, moves mail containing "it"/"security" to RSS Feeds, marks read | Persistence / defense evasion | n/a |

Full tool output: [`artifacts/case01_credential_harvest_iocs.md`](artifacts/case01_credential_harvest_iocs.md)

## 4. Investigation Steps

1. **Header analysis** (raw `.eml`): SPF fail and DMARC fail on the From domain; Return-Path domain differs from From; origin IP has no valid rDNS. `eml_analyzer.py` scored it 12 (LIKELY MALICIOUS) and flagged the look-alike domain and the link mismatch.
2. **Scoping, recipients**: 3 recipients from the `To` header. In production I'd confirm with a mail-gateway trace by Message-ID `<20260914121244.4471@mailer-cloudsend.example>`.
3. **Scoping, interaction** (`case01_proxy_logs.csv`, filtered on `ridgeline-sso-verify`):
   - **jsmith**: GET 08:31:52 → **POST to `/auth/submit` 08:32:40** → redirected to the real portal 08:32:41. The redirect to the real site is a common way to keep the victim from noticing anything. **Credentials submitted.**
   - **apatel**: GET 08:47:13, **no POST**. Page loaded, no credentials submitted.
   - **mlee**: no requests to the phishing domain. Reported the email.
4. **Compromise check** (`case01_signin_logs.csv`): jsmith normally signs in from corporate egress `192.0.2.50` (Wheeling, Windows/Edge). Starting 09:14, sign-ins came from `203.0.113.200` (VPS):
   - 09:14:03 and 09:14:40: **failures, MFA denied**, UA `python-requests`. The password was **correct**; only MFA stopped it.
   - 09:16:02: **success, MFA push approved** by the user. That's MFA fatigue / push bombing (T1621).
   - 09:18:55: session reuse from the same IP, now with a browser UA (Linux/Firefox).
   - apatel shows only normal corporate sign-ins, so no evidence of compromise.
5. **Post-compromise activity** (`case01_mailbox_audit.csv`, all from `203.0.113.200`):
   - 09:19:30 `New-InboxRule` named `.` hides mail from IT/security by moving it to RSS Feeds and marking it read. This keeps the victim from seeing security warnings or replies.
   - 09:21:12 mailbox search for `invoice OR wire OR payment`, i.e. looking for financial workflows.
   - 09:26:48 **sent email to `ap-team@` with the subject "Updated banking details for vendor payments"**. Internal spearphishing / payment fraud (T1534).
6. **Timeline built** with `build_timeline.py` by merging the email, proxy, sign-in, and audit logs (Section 6).

## 5. Affected Users & Systems

| User | Received | Clicked | Submitted creds | Account compromised | Notes |
|---|---|---|---|---|---|
| jsmith | Yes | Yes | **Yes** | **Yes** | Approved MFA push; mailbox used for internal BEC |
| apatel | Yes | Yes | No | No | Loaded page only; monitor |
| mlee | Yes | No | No | No | Reporter |
| ap-team (DL) | Internal email from jsmith | Unknown | n/a | n/a | **Received fraudulent banking-details email** |

## 6. Timeline (all times -04:00, 2026-09-14)

| Time | Source | Event |
|---|---|---|
| 08:12:44 | Email | Phish sent from `ridgeIine-support[.]example` via `203.0.113.77` |
| 08:12:47 | Email | Delivered to jsmith, apatel, mlee |
| 08:31:52 | Proxy | jsmith opens phishing page |
| **08:32:40** | Proxy | **jsmith POSTs credentials** to `/auth/submit` |
| 08:32:41 | Proxy | jsmith redirected to real portal (concealment) |
| 08:47:13 | Proxy | apatel opens phishing page (no submission) |
| 09:14:03 | Sign-in | Attacker login, correct password, MFA denied (`python-requests`) |
| 09:14:40 | Sign-in | Second attempt, MFA denied |
| **09:16:02** | Sign-in | **Attacker login succeeds, MFA push approved by user** |
| 09:18:55 | Sign-in | Attacker session reused (browser) |
| 09:19:30 | Mailbox audit | Hidden inbox rule `.` created |
| 09:21:12 | Mailbox audit | Mailbox searched for invoice / wire / payment |
| **09:26:48** | Mailbox audit | **Fraudulent "updated banking details" email sent to ap-team** |

**Click to credential theft: 48 seconds. Credential theft to account takeover: 43 minutes. Takeover to fraud attempt: 11 minutes.**

Full merged timeline: [`artifacts/case01_full_timeline.csv`](artifacts/case01_full_timeline.csv)

## 7. Findings / Analysis

**Confirmed**
- jsmith's credentials were phished and used by an external actor from `203.0.113.200`.
- MFA was bypassed because the user approved a push notification, not through a technical flaw.
- The attacker set up persistence/evasion (inbox rule) and used the account to send an internal payment-fraud email to AP.

**Suspected / needs verification**
- Whether anyone in AP acted on the banking-details email. **This is the highest business risk.**
- Whether the attacker read or exported other mail (need full `MailItemsAccessed` audit).
- Whether the same infrastructure targeted other users beyond these 3 (org-wide gateway and proxy search).
- AP was targeted again the next day (PHISH-2026-002). Different sender infrastructure, so there's **no confirmed link**, but AP is clearly a target.

## 8. Containment & Response Actions

**Immediate (containment)**
- [ ] Disable jsmith sign-in, **reset password, and revoke all sessions / refresh tokens**
- [ ] Delete inbox rule `.` and check for mail forwarding or new MFA methods added by the attacker
- [ ] **Contact AP by phone/in person:** do not act on "Updated banking details" email; freeze any vendor banking changes made on/after 2026-09-14
- [ ] Purge the internal fraud email from ap-team mailboxes
- [ ] Purge the original phish from all mailboxes (by Message-ID / sender domain)
- [ ] Block `ridgeIine-support[.]example`, `ridgeline-sso-verify[.]example`, `mailer-cloudsend[.]example` at mail gateway + DNS/proxy
- [ ] Block / alert on sign-ins from `203.0.113.200`

**Eradication / recovery**
- [ ] Full mailbox audit review for jsmith (mail read, sent, deleted) for 09:16 onward
- [ ] Re-register jsmith MFA; confirm no attacker-controlled methods remain
- [ ] Monitor apatel sign-ins for 14 days (page visited, no submission)
- [ ] Org-wide search of proxy logs for any other hits on the phishing domain

**Follow-up / lessons learned**
- [ ] **Enable MFA number matching** (or phishing-resistant FIDO2) to defeat push fatigue
- [ ] Alert on new inbox rules that move to RSS Feeds/Archive or have 1-character names
- [ ] Add look-alike domain monitoring for `ridgeline.example`
- [ ] Short coaching session with jsmith on MFA prompts they didn't initiate; recognize mlee for reporting
- [ ] Require out-of-band verification for any vendor banking change (AP policy)

## 9. Escalation

Escalated **immediately to Tier 2 / IR lead and SOC manager**, and to **Finance leadership**, per playbook criteria: confirmed account takeover with attacker activity **and** payment fraud in progress (Critical).

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566.002 Spearphishing Link | Link to `ridgeline-sso-verify[.]example` |
| Defense Evasion | T1656 Impersonation | Poses as internal IT Service Desk; look-alike domain |
| Credential Access | T1621 MFA Request Generation | Repeated MFA prompts, then user approval |
| Initial Access / Persistence | T1078 Valid Accounts | Logins with jsmith's stolen password |
| Defense Evasion | T1564.008 Email Hiding Rules | Rule `.` hides IT/security mail |
| Collection | T1114.002 Remote Email Collection | Mailbox search for invoice/wire/payment |
| Lateral Movement | T1534 Internal Spearphishing | Fraud email from jsmith to ap-team |
