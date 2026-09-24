# Phishing Triage & Escalation Playbook

## Triage Flow

```
User report / alert
      │
      ▼
1. Pull raw email (.eml) ── headers, auth results, URLs, attachments
      │
      ▼
2. Malicious indicators?  ── No ──► Document as benign, notify reporter, close
      │ Yes / Unsure
      ▼
3. Scope: who else received it? (search mail gateway by sender, subject, URL, hash)
      │
      ▼
4. Interaction: who clicked (proxy/DNS logs)? who opened attachment (EDR)? who replied?
      │
      ▼
5. Compromise check: sign-in logs for affected users (new IP/geo/UA, MFA anomalies)
      │
      ▼
6. Assign severity ──► Contain ──► Escalate per matrix ──► Document
```

## Severity Matrix

| Severity | Criteria | Escalate to | Target response |
|---|---|---|---|
| **Critical** | Confirmed account takeover **with** attacker activity (inbox rules, internal phishing, data access) or payment fraud in progress | Tier 2/IR lead + manager immediately | Immediate |
| **High** | Credentials submitted **or** malicious attachment executed, no confirmed attacker use yet | Tier 2 | < 1 hour |
| **Medium** | Malicious email delivered to users, clicks with no data submitted | Handle at Tier 1, notify Tier 2 | < 4 hours |
| **Low** | Malicious email delivered, no interaction; or blocked/quarantined | Tier 1 | < 24 hours |
| **Informational** | Benign / spam / simulation | Close | Next business day |

**Always escalate regardless of severity:** executive targeted with BEC, any financial/payment request, anything involving sensitive data, or when you're unsure.

## Standard Containment Actions

**Email**
- Purge the message from all mailboxes (search by Message-ID / sender / subject)
- Block sender domain, URLs, and attachment hash at the mail gateway
- Block malicious domains/URLs at proxy/DNS

**Compromised account**
- Reset password **and** revoke all active sessions/tokens
- Review and re-register MFA methods; remove attacker-added methods
- Remove malicious inbox rules / forwarding
- Review mailbox audit log for mail sent, searched, or accessed
- Notify recipients of any internal phishing sent from the account

**Financial / BEC**
- Contact Finance/AP to halt pending payments or changes to banking details
- Verify vendor requests via a **known-good** phone number, never contact info from the email

**User**
- Thank the reporter (reporting behavior should be reinforced)
- Targeted awareness follow-up for users who clicked, framed as coaching, not punishment

## Relevant MITRE ATT&CK Techniques

| ID | Name |
|---|---|
| T1566.001 | Phishing: Spearphishing Attachment |
| T1566.002 | Phishing: Spearphishing Link |
| T1656 | Impersonation |
| T1621 | Multi-Factor Authentication Request Generation |
| T1078 | Valid Accounts |
| T1564.008 | Hide Artifacts: Email Hiding Rules |
| T1534 | Internal Spearphishing |
| T1114.002 | Email Collection: Remote Email Collection |
| T1056.003 | Input Capture: Web Portal Capture |
| T1585.002 | Establish Accounts: Email Accounts |
