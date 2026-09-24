# Lab Walkthrough

You are a Tier 1 SOC analyst at **Ridgeline Logistics** (fictional). Over one week, four emails were reported to the SOC. Your job for each one: **triage → investigate → decide → document → escalate if needed.**

> All domains use the reserved `.example` TLD and all IPs are documentation ranges (RFC 5737). None of them resolve or route. Threat-intel lookups on these IOCs will return nothing. That's expected. Part 4 shows how to practice the lookup workflow safely on real indicators.

---

## Part 0: Setup (10 min)

```bash
git clone https://github.com/Theyloveyoni/Phishing-investigation-lab.git
cd Phishing-investigation-lab
python3 tools/generate_samples.py      # rebuilds samples/ (optional, already included)
python3 tools/eml_analyzer.py --help
```

No dependencies beyond Python 3.8+. Open `.eml` files in a **text editor** (VS Code, TextEdit in plain-text mode), not a mail client. You want the raw headers.

---

## Part 1: Manual header analysis first (do NOT run the tool yet)

For each `samples/case0X_*.eml`, open the raw file and answer these in your notes:

1. Who does it **claim** to be from (display name)? What is the **actual** sender address?
2. Do `From`, `Reply-To`, and `Return-Path` share a domain? If not, why does that matter?
3. Read `Authentication-Results`. What do SPF, DKIM, and DMARC each say?
4. Read the `Received` headers **bottom to top**. What is the originating IP and hostname?
5. Hover-equivalent: in the HTML part, does any link's visible text differ from its `href`?
6. Is there an attachment? What type? Would it execute or render something?
7. What pressure tactics are used (urgency, authority, secrecy, fear)?

**Only after that**, run the tool and compare it with your manual findings:

```bash
python3 tools/eml_analyzer.py samples/case01_credential_harvest.eml
```

Write down anything you caught that the tool didn't, or the reverse.

---

## Part 2: Case investigations

### Case 01: Credential harvesting (the full incident)

Reported by `mlee`, who didn't click. The email went to 3 users.

**Triage:** run the analyzer. Note the look-alike domain `ridgeIine-support.example` (capital **I**, not lowercase **l**) and the link whose display text doesn't match its destination.

**Scope: who clicked?** Open `samples/case01_proxy_logs.csv`.
```bash
grep "ridgeline-sso-verify" samples/case01_proxy_logs.csv
```
- Who only loaded the page (GET)?
- Who **submitted** data (POST)? That user must be treated as having entered credentials.

**Compromise check: did the attacker use the password?** Open `samples/case01_signin_logs.csv`.
- Find sign-ins from an IP that isn't the corporate egress `192.0.2.50`.
- Note the user agent change (`python-requests` means scripted), the failures, then a **success after an MFA push was approved**. What attack pattern is that? (Hint: MFA fatigue / push bombing.)

**Post-compromise activity: what did they do?** Open `samples/case01_mailbox_audit.csv`.
- What does the inbox rule do, and why would an attacker hide mail from "IT" and "security"?
- What did the attacker search for? Who did they email, and about what?
- Connect this to Case 02's target team. What's the attacker's likely end goal?

**Build a timeline** in UTC or consistent local time: email delivered → click → credential POST → failed logins → MFA approval → inbox rule → search → internal phishing email sent.

**Decide:** severity (use the matrix in `docs/escalation-playbook.md`), affected users (`jsmith` compromised, `apatel` exposed, `mlee` reporter), and containment actions.

### Case 02: Invoice with HTML attachment

- Why is an `.html` attachment risky even though it isn't an `.exe`? (It opens a local, offline-looking phishing form in the browser. Many mail filters don't inspect it the same way they inspect links.)
- Extract the SHA-256. In a real SOC you'd search it in VirusTotal and across your mail gateway for other recipients.
- Open the attachment **as text** and find where the form submits (`action=`). That's another IOC.
- Reply-To points to a free-mail domain, not the vendor's. Who at Pinecrest would you call, and **how** (hint: not using contact info from the email)?

### Case 03: CEO gift card / BEC

- The tool says **LOW RISK** and all authentication passes. Explain why SPF/DKIM/DMARC "pass" doesn't mean "legitimate". It only proves the email really came from `quickmail-free.example`.
- List the social-engineering indicators the tool can't see: external free-mail address using the CEO's name, secrecy, urgency, gift cards, "sent from my phone", request to bypass normal process.
- Did `rgarcia` reply or buy anything? (Assume unknown. What would you ask them, and what logs would you check?)

### Case 04: Benign HR notice (false-positive practice)

- Verify it's legitimate: internal relay, full auth pass, link to a first-party domain, expected seasonal content.
- Document it as **benign / closed – no action**. Knowing when to close a ticket fast is half the job.

---

## Part 3: Write the reports

Copy `templates/incident_report_template.md` into `reports/` for each case:

```bash
cp templates/incident_report_template.md reports/case01_report.md
python3 tools/eml_analyzer.py samples/case01_credential_harvest.eml --md > reports/case01_iocs.md
```

Write the analysis sections **in your own words**. This is what employers read.

---

## Part 4: Threat-intel practice on real indicators (safely)

The lab IOCs are fictional, so practice the lookup workflow with real, public indicators:

| Resource | What to use it for |
|---|---|
| [VirusTotal](https://www.virustotal.com) | File hashes, URLs, domains, IPs |
| [URLScan.io](https://urlscan.io) | Look at **existing** public scans of phishing pages: screenshots, redirects, hosting |
| [AbuseIPDB](https://www.abuseipdb.com) | IP reputation and abuse reports |
| [MXToolbox](https://mxtoolbox.com) | Header analyzer, SPF/DMARC lookups for real domains |
| `whois` / [ICANN Lookup](https://lookup.icann.org) | Domain registration date (newly registered = red flag) |
| [PhishTank](https://phishtank.org) / [OpenPhish](https://openphish.com) | Public feeds of reported phishing URLs |

**Exercise:** pick 3 recent URLs from a public phishing feed. For each, **without visiting it**, record: domain age (WHOIS), hosting IP + ASN, VirusTotal detections, and an existing URLScan screenshot. Summarize in `reports/threat_intel_practice.md` with every indicator **defanged**.

> Safety rules: never open phishing URLs in your normal browser, never enter data, never download samples to your host. Look things up; don't visit them.

**Bonus:** forward a real spam/phish from your own inbox (not work/school mail) as an attachment, save it as `.eml`, and analyze it. **Redact your email address and name before committing it.**

---

## Part 5: Stretch goals (make the tool yours)

Each of these is a good commit that shows you understand the gaps:

- [x] Detect look-alike domains (homoglyph map + Levenshtein vs. protected domains)
- [x] Flag a display name that matches an executive list when sent from an external domain (catches Case 03)
- [x] Flag free-mail sender domains
- [x] Output a timeline by merging the proxy, sign-in, and audit logs (`tools/build_timeline.py`)
- [ ] Add optional VirusTotal API lookups for hashes/URLs (read key from an env var, never commit it)
- [ ] Detect Unicode/IDN homoglyph domains (punycode `xn--`)
