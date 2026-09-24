#!/usr/bin/env python3
"""
build_timeline.py - Merge email delivery + log sources into one chronological timeline.

Usage:
    python3 tools/build_timeline.py --email samples/case01_credential_harvest.eml \
        --logs samples/case01_proxy_logs.csv samples/case01_signin_logs.csv samples/case01_mailbox_audit.csv
    ... --filter jsmith 203.0.113.200 ridgeline-sso-verify   # keep only matching rows
    ... --csv > reports/case01_timeline.csv

Each CSV must have a 'timestamp' column (ISO 8601). Other columns are summarized
into an event description. Standard library only.
"""

import argparse
import csv
import email
import os
import sys
from datetime import datetime
from email import policy
from email.utils import parsedate_to_datetime


def describe(source, row):
    if "operation" in row:  # mailbox audit
        return f"{row.get('user')} from {row.get('src_ip')}: {row['operation']} - {row.get('details', '')}"
    if "mfa" in row:  # sign-in log
        return (f"Sign-in {row.get('result', '').upper()} for {row.get('user')} from {row.get('src_ip')} "
                f"({row.get('geo')}, {row.get('user_agent')}), MFA: {row.get('mfa')}")
    if "url" in row:  # proxy log
        return f"{row.get('user')} ({row.get('src_ip')}) {row.get('method')} {row.get('url')} -> {row.get('status')}"
    return "; ".join(f"{k}={v}" for k, v in row.items() if k != "timestamp")


def email_events(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    events = []
    sent = parsedate_to_datetime(str(msg["Date"]))
    events.append((sent, "email", f"Email sent: '{msg['Subject']}' from {msg['From']}"))
    received = msg.get_all("Received", []) or []
    if received:
        last_hop = str(received[0]).rsplit(";", 1)[-1].strip()
        try:
            events.append((parsedate_to_datetime(last_hop), "email",
                           f"Email delivered to: {msg['To']}"))
        except (TypeError, ValueError):
            pass
    return events


def main():
    ap = argparse.ArgumentParser(description="Build an incident timeline")
    ap.add_argument("--email", nargs="*", default=[])
    ap.add_argument("--logs", nargs="*", default=[])
    ap.add_argument("--filter", nargs="*", default=[], help="keep events containing any of these strings")
    ap.add_argument("--csv", action="store_true", help="CSV output instead of Markdown")
    args = ap.parse_args()

    events = []
    for e in args.email:
        events.extend(email_events(e))
    for path in args.logs:
        src = os.path.basename(path).replace(".csv", "")
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                events.append((datetime.fromisoformat(row["timestamp"]), src, describe(src, row)))

    if args.filter:
        events = [ev for ev in events if ev[1] == "email" or
                  any(term.lower() in ev[2].lower() for term in args.filter)]
    events.sort(key=lambda ev: ev[0])

    if args.csv:
        w = csv.writer(sys.stdout)
        w.writerow(["timestamp", "source", "event"])
        for ts, src, desc in events:
            w.writerow([ts.isoformat(), src, desc])
    else:
        print("| Time | Source | Event |\n|---|---|---|")
        for ts, src, desc in events:
            print(f"| {ts.strftime('%Y-%m-%d %H:%M:%S %z')} | {src} | {desc.replace('|', '/')} |")


if __name__ == "__main__":
    main()
