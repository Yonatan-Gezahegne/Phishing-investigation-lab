# Interview Prep: Phishing Investigation Lab

You should be able to answer every question here **out loud, without notes**. Short answers are included so you can check yourself.

## The 60-second pitch

> "I built a phishing investigation lab around a fictional company. I wrote a Python triage tool that parses raw emails, checks SPF, DKIM, and DMARC, traces the Received headers, pulls out and defangs the IOCs, hashes attachments, and scores red flags. The main case is a credential phish that turned into an account takeover. By correlating proxy, sign-in, and mailbox-audit logs, I showed the user submitted their password, the attacker got past MFA through push fatigue, created a hidden inbox rule, and sent a fake banking-details email to Accounts Payable. The most interesting part was a CEO gift-card scam that passed all email authentication, so my tool first scored it low risk. I added executive-impersonation detection and a regression test to fix it."

## Must-know questions

**1. What do SPF, DKIM, and DMARC each check?**
SPF: is the sending IP allowed to send for the envelope-from (Return-Path) domain? DKIM: is the message cryptographically signed by a domain, and unaltered? DMARC: does the visible From domain align with a passing SPF or DKIM domain, and what should the receiver do on failure (none/quarantine/reject)?

**2. Case 03 passed all three. How is that possible?**
It was really sent from a free-mail provider, so authentication passed *for that provider's domain*. DMARC protects domains from spoofing. It does nothing about someone using the CEO's name as the display name on their own account.

**3. How do you read Received headers?**
Bottom to top. Each server prepends its header, so the lowest one is closest to the sender. The originating IP is in the bottom-most external hop.

**4. How did you tell who clicked vs. who was compromised?**
Proxy logs. A GET to the phishing page means they opened it. A **POST** to `/auth/submit` means they submitted data. apatel only did a GET; jsmith did a POST.

**5. How did you know the attacker had the correct password?**
The first sign-in attempts from the VPS failed at the **MFA** step, not the password step. The password worked; only MFA stopped them, until the user approved a push.

**6. What is MFA fatigue and how do you prevent it?**
The attacker keeps triggering push prompts until the user approves one. Fixes: number matching, phishing-resistant MFA (FIDO2/passkeys), alerting on repeated denied prompts, and user training.

**7. Why would an attacker create an inbox rule named "."?**
Persistence and hiding. It moves mail from IT/security into a rarely viewed folder and marks it read, so the victim never sees warnings or replies to the attacker's emails. The one-character name makes it easy to miss.

**8. Why is an .html attachment dangerous?**
It renders a fake login page locally in the browser, so no URL is visible in the email body for filters to scan, and it looks like a document viewer.

**9. First 3 containment steps for a compromised mailbox?**
Reset password **and revoke sessions/tokens** (a reset alone doesn't kill active sessions), remove malicious inbox rules/forwarding and attacker-added MFA methods, then find and clean up anything sent from the account.

**10. Why block the attacker's free-mail *address* and not the whole domain?**
Blocking a whole free-mail provider would block legitimate customers and vendors.

**11. What does "defanging" mean and why do it?**
Changing `http` to `hxxp` and `.` to `[.]` so indicators can't be clicked by accident or auto-linked in reports and tickets.

**12. What's the weakness of your tool?**
It's rule-based: keyword urgency detection is easy to evade, look-alike detection only covers domains I configure, and it has no live threat-intel lookups. The next steps would be VirusTotal API enrichment and a homoglyph list for Unicode (IDN) domains.

## Be honest about scope

It's a **simulated** lab with a fictional dataset. Say that plainly. Interviewers respect "I built a realistic simulation and here's what I learned" far more than overclaiming real-world incident response. Your co-op work at the CRRC is where you talk about real environments.

## Before your interview, do these yourself

- [ ] Clone the repo on your laptop and run every command in the README
- [ ] Open `samples/case01_credential_harvest.eml` in a text editor and find the look-alike domain and the mismatched link by eye
- [ ] Rebuild the Case 01 timeline with `build_timeline.py` and explain each row
- [ ] Do the real-indicator threat-intel exercise in `docs/walkthrough.md` Part 4
