# Incident Report: PHISH-2026-002 Malicious HTML "Invoice" Attachment

| Field | Value |
|---|---|
| **Case ID** | PHISH-2026-002 |
| **Analyst** | Yonatan Gezahegne |
| **Date reported** | 2026-09-15 |
| **Reported by** | AP team member |
| **Classification** | Credential phishing via HTML attachment (vendor impersonation) |
| **Severity** | **Medium** (raise to High if any recipient submitted credentials) |
| **Status** | Contained (pending interaction verification) |

## 1. Executive Summary

The Accounts Payable team received an "overdue invoice" email that appears to come from vendor Pinecrest Supply. The attachment `Invoice_88213.html` is not an invoice: it's a local phishing page with a fake sign-in form that sends email and password to `docview-secure-share[.]example`. The email failed SPF, DKIM, and DMARC, and replies go to a free-mail address. So far there's no evidence anyone submitted credentials. The message has been purged and its indicators blocked.

## 2. Initial Evidence

- **Subject:** `Overdue invoice #88213 - final notice`
- **Sender (display / address):** `Pinecrest Supply Accounts` / `accounts@pinecrest-supply[.]example`
- **Reply-To:** `pinecrest.billing.dept@quickmail-free[.]example` (**free-mail, not the vendor's domain**)
- **Return-Path:** `accounts@pinecrest-supply[.]example`
- **Recipients:** `ap-team@ridgeline.example` (distribution list)
- **SPF / DKIM / DMARC:** softfail / fail / fail (DMARC policy `quarantine`)
- **Originating IP / host:** `198.51.100[.]23`. HELO claimed `mail.pinecrest-supply[.]example` but rDNS is `vps-host.cheap-cloud[.]example`, **so the HELO and reverse DNS don't match**
- **Delivery time:** 2026-09-15 14:03:12 -04:00

## 3. Indicators of Compromise (defanged)

| Type | Indicator | Context | TI Result |
|---|---|---|---|
| File (SHA-256) | `e8eae359f834670a5a486e3a19588ae2d5870a9e6966f839cc19ac11748a9633` | `Invoice_88213.html` | Lab IOC. In production: VirusTotal hash search |
| File (MD5) | `ed8771d1b859741c50a09c77aa0823ad` | Same file | Lab IOC |
| URL | `hxxps://docview-secure-share[.]example/collect.php` | Form `action=` credential exfil endpoint | Lab IOC |
| Email | `pinecrest.billing.dept@quickmail-free[.]example` | Attacker-controlled Reply-To | Lab IOC |
| IP | `198.51.100[.]23` | Sending host (VPS) | Lab IOC |
| Host | `vps-host.cheap-cloud[.]example` | rDNS of sending IP | Lab IOC |

Full tool output: [`artifacts/case02_invoice_attachment_iocs.md`](artifacts/case02_invoice_attachment_iocs.md)

## 4. Investigation Steps

1. **Header analysis:** All three authentication checks failed for `pinecrest-supply[.]example`, meaning the sending server isn't authorized by the vendor's domain. The HELO/rDNS mismatch shows a generic VPS pretending to be the vendor's mail server.
2. **Sender analysis:** From is the vendor's domain, but **Reply-To is a free-mail account**. Any reply would go to the attacker, a common setup for continuing the conversation into payment fraud.
3. **Attachment analysis:** Opened `Invoice_88213.html` **as plain text only** (not rendered in a browser). It contains an HTML form with email and password fields that POSTs to `docview-secure-share[.]example/collect.php`. HTML attachments are used because they render locally and can slip past URL-scanning controls.
4. **Hashing:** Calculated SHA-256/MD5 with `eml_analyzer.py` for threat-intel and gateway searches. Automated score: 8 (LIKELY MALICIOUS).
5. **DMARC anomaly:** The domain publishes `p=quarantine`, but the message was reported from a user's mailbox. Either a user released it from junk/quarantine or a gateway allow rule overrode the policy. **Needs verification**: an allow-list entry for this vendor would be a control gap.
6. **Interaction check:** No proxy/DNS data for 2026-09-15 is in the lab dataset. In production I'd search proxy and DNS logs for `docview-secure-share` and EDR for `Invoice_88213.html` opened by any AP member.

## 5. Affected Users & Systems

| User | Received | Clicked / opened | Submitted creds | Account compromised | Notes |
|---|---|---|---|---|---|
| ap-team DL members | Yes | Unknown | Unknown | Unknown | Verify via proxy/DNS/EDR |

## 6. Timeline (2026-09-15, -04:00)

| Time | Source | Event |
|---|---|---|
| 14:03:10 | Email Date header | Email composed/sent |
| 14:03:12 | Received header | Accepted by `mx-edge` from `198.51.100.23` |
| 14:03:14 | Received header | Delivered to internal `mx1` |
| (later) | User report | AP member reports email to SOC |

## 7. Findings / Analysis

**Confirmed:** Malicious credential-phishing attachment; spoofed vendor identity; attacker-controlled reply channel.

**Suspected:** Pinecrest Supply may not be compromised. Authentication failures point to **spoofing**, not a hijacked vendor mailbox. This came one day after the attacker in PHISH-2026-001 sent AP a "banking details" email. The infrastructure is different, so there's **no confirmed link**, but AP is being targeted repeatedly.

## 8. Containment & Response Actions

**Immediate**
- [ ] Purge message from all mailboxes (Message-ID `<CAF88213.9921@pinecrest-supply.example>`)
- [ ] Block file hash, `docview-secure-share[.]example`, the free-mail Reply-To **address** (not the whole free-mail domain), and `198.51.100.23`
- [ ] Search proxy/DNS/EDR for any interaction; if a POST is found, treat as PHISH-2026-001 (reset + revoke sessions)

**Recovery / follow-up**
- [ ] Notify Pinecrest Supply **using a phone number from our vendor records, not the email** that their brand is being spoofed
- [ ] Review gateway allow-lists; confirm DMARC quarantine is honored
- [ ] Consider blocking or sandboxing inbound `.html`/`.htm` attachments
- [ ] AP team briefing: two phishing attempts in two days

## 9. Escalation

Tier 1 handled containment. **Notified Tier 2 and AP management** because the target is a finance team and it's related in timing to a Critical incident. Upgrade to High if interaction is found.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566.001 Spearphishing Attachment | `Invoice_88213.html` |
| Defense Evasion | T1656 Impersonation | Poses as vendor Pinecrest Supply |
| Credential Access | T1056.003 Input Capture: Web Portal Capture | Fake sign-in form posting to attacker endpoint |
