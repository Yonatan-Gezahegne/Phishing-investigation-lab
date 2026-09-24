# Incident Report: PHISH-2026-003 CEO Impersonation Gift-Card Scam (BEC)

| Field | Value |
|---|---|
| **Case ID** | PHISH-2026-003 |
| **Analyst** | Yonatan Gezahegne |
| **Date reported** | 2026-09-16 |
| **Reported by** | rgarcia (recipient) |
| **Classification** | Business Email Compromise, executive impersonation |
| **Severity** | **High** (financial request + executive impersonation; always escalated per playbook) |
| **Status** | Contained. Recipient confirmed with SOC before acting (lab assumption) |

## 1. Executive Summary

An email using CEO **Dana Whitfield's** name asked employee **rgarcia** to buy six $200 gift cards ($1,200) and send photos of the codes, marked "urgent" and "confidential." It came from a free-mail account, not our domain. It **passed SPF, DKIM, and DMARC**, because it really was sent from that free-mail provider. It had no links or attachments, so there was nothing for automated scanning to catch. This case shows the gap between *authenticated* and *legitimate*.

## 2. Initial Evidence

- **Subject:** `Quick favor - confidential`
- **Sender (display / address):** `Dana Whitfield` / `dana.whitfield.ceo@quickmail-free[.]example`
- **Reply-To / Return-Path:** same free-mail address
- **Recipients:** rgarcia@ridgeline.example
- **SPF / DKIM / DMARC:** **pass / pass / pass** (for `quickmail-free[.]example`)
- **Originating IP / host:** `198.51.100[.]140` (`out-19.quickmail-free[.]example`, a legitimate free-mail outbound server)
- **Delivery time:** 2026-09-16 16:47:33 -04:00 (late afternoon, when people are rushing)

## 3. Indicators of Compromise (defanged)

| Type | Indicator | Context | TI Result |
|---|---|---|---|
| Email | `dana.whitfield.ceo@quickmail-free[.]example` | Impersonator's account | Lab IOC |
| Display name | `Dana Whitfield` from external domain | Executive impersonation | n/a |

No URLs, attachments, or malicious infrastructure. **The "payload" is the social engineering itself.**

## 4. Investigation Steps

1. **Header analysis:** All authentication passed. Checked *which domain* passed: `quickmail-free[.]example`, not `ridgeline.example`. DMARC only confirms that the From domain wasn't spoofed. It says nothing about whether the person is who they claim to be.
2. **First automated result was wrong:** the first version of `eml_analyzer.py` scored this **1/LOW RISK**. The only signal it had was urgency language.
3. **Manual social-engineering analysis:**
   - Executive name from an **external free-mail** address (the CEO would use corporate mail)
   - **Urgency** ("this afternoon") + **authority** (CEO) + **secrecy** ("don't mention it to anyone")
   - **Gift cards**: untraceable, irreversible payment
   - "In back-to-back meetings" / "Sent from my phone", which pre-empts any attempt to call and verify
   - Asks the employee to go around normal purchasing
4. **Tool improvement:** added executive-impersonation detection (external sender + display name on the `EXECUTIVES` list) and free-mail detection to the analyzer. Re-scored at **5/LIKELY MALICIOUS**. A regression test now keeps this case caught.
5. **Interaction check:** confirm with rgarcia (by phone/in person, not by replying) whether she replied or bought anything. Run a mail trace for any outbound mail from rgarcia to the attacker address.

## 5. Affected Users & Systems

| User | Received | Replied | Purchased | Notes |
|---|---|---|---|---|
| rgarcia | Yes | No (to be confirmed by trace) | No (to be confirmed) | Reported; did the right thing |
| Dana Whitfield (CEO) | n/a | n/a | n/a | Name impersonated; notify |

## 6. Timeline (2026-09-16, -04:00)

| Time | Source | Event |
|---|---|---|
| 16:47:31 | Date header | Email sent from free-mail provider |
| 16:47:33 | Received header | Accepted by `mx-edge` from `198.51.100.140` |
| 16:47:35 | Received header | Delivered to rgarcia |
| (later) | User report | rgarcia reports to SOC |

## 7. Findings / Analysis

**Confirmed:** An external actor impersonated the CEO to request untraceable payment. No technical compromise of any Ridgeline system.

**Key lesson:** Email authentication (SPF/DKIM/DMARC) protects **domains**, not **display names**. Detecting BEC needs context (who our executives are, which domains we own) plus human judgment. A tool that only checks authentication and links misses the entire attack.

## 8. Containment & Response Actions

**Immediate**
- [ ] Block the specific sender **address** (not all of `quickmail-free[.]example`, which would block legitimate mail)
- [ ] Search all mailboxes for mail from this address or with display name "Dana Whitfield" from external domains; purge
- [ ] Confirm with rgarcia out-of-band that no reply or purchase happened

**Follow-up**
- [ ] Notify the CEO and the executive assistants that the CEO is being impersonated
- [ ] Enable gateway **display-name impersonation protection** for executives
- [ ] Add an **"[EXTERNAL]" banner** to inbound mail
- [ ] Awareness note: leadership will never request gift cards by email
- [ ] Recognize rgarcia for reporting

## 9. Escalation

Escalated to **Tier 2 and SOC manager** per playbook ("always escalate: executive targeted with BEC / any financial request"). CEO's office notified.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Resource Development | T1585.002 Establish Accounts: Email Accounts | Free-mail account named after the CEO |
| Defense Evasion | T1656 Impersonation | CEO display name, authority and urgency |
| Initial Access | T1566 Phishing (no link/attachment) | Social-engineering request by email |
