#!/usr/bin/env python3
"""
eml_analyzer.py - Phishing triage helper.

Parses a raw .eml file and pulls out the evidence an analyst needs for triage:
  * Key headers (From, Reply-To, Return-Path, Subject, Date, Message-ID)
  * SPF / DKIM / DMARC verdicts from Authentication-Results
  * Received-hop chain (the path the email took) + originating IP
  * Sender mismatches (From vs Reply-To vs Return-Path domains)
  * URLs in the body (defanged), including href/display-text mismatches
  * Attachments with SHA-256 / MD5 hashes
  * Simple red-flag scoring to help prioritize

Standard library only. Usage:
    python3 tools/eml_analyzer.py samples/case01_credential_harvest.eml
    python3 tools/eml_analyzer.py samples/*.eml --json
    python3 tools/eml_analyzer.py samples/case02.eml --md > reports/case02_iocs.md
"""

import argparse
import email
import hashlib
import json
import re
import sys
from email import policy
from email.utils import parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
IP_RE = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
URGENCY_WORDS = [
    "urgent", "immediately", "suspended", "verify", "within 24 hours",
    "action required", "final notice", "password expires", "unusual activity",
    "gift card", "wire", "confidential", "overdue",
]
RISKY_EXT = (".html", ".htm", ".js", ".vbs", ".exe", ".scr", ".iso", ".img",
             ".lnk", ".docm", ".xlsm", ".zip", ".rar", ".one", ".hta")

# ---- Organization context (edit these for your own environment) ----
PROTECTED_DOMAINS = ["ridgeline.example"]          # domains we own
EXECUTIVES = ["dana whitfield"]                     # names attackers impersonate
FREEMAIL_DOMAINS = ["quickmail-free.example", "gmail.com", "outlook.com", "hotmail.com",
                    "yahoo.com", "aol.com", "icloud.com", "proton.me", "protonmail.com"]

# Characters attackers swap to build look-alike domains (normalized to one form)
HOMOGLYPHS = str.maketrans({"i": "l", "1": "l", "|": "l", "0": "o", "5": "s", "3": "e", "@": "a"})

# Weighted red flags: stronger evidence counts more
WEIGHTS = {"auth": 1, "sender_mismatch": 1, "link_mismatch": 2, "lookalike": 3,
           "brand_in_url": 2, "exec_impersonation": 3, "freemail": 1,
           "risky_attachment": 2, "urgency": 1}


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_protected(domain: str) -> bool:
    return any(domain == p or domain.endswith("." + p) for p in PROTECTED_DOMAINS)


def lookalike_of(domain: str):
    """Return the protected domain this one imitates, or None.

    Splits the domain into tokens (ridgeiine-support.example -> ridgeiine, support),
    normalizes homoglyphs, and checks for an exact or near (edit distance <= 1) match
    against each protected brand name. Exact, un-normalized brand matches are
    handled separately as 'brand_in_url'.
    """
    domain = domain.lower()
    if not domain or is_protected(domain):
        return None
    tokens = re.split(r"[.\-_]", domain)
    for p in PROTECTED_DOMAINS:
        brand = p.split(".")[0]
        for t in tokens:
            if t == brand:
                continue  # exact brand word -> brand_in_url check, not a homoglyph trick
            if t.translate(HOMOGLYPHS) == brand.translate(HOMOGLYPHS) or \
               (len(t) >= 5 and levenshtein(t, brand) == 1):
                return p
    return None


def brand_in_domain(domain: str):
    domain = domain.lower()
    if not domain or is_protected(domain):
        return None
    tokens = re.split(r"[.\-_]", domain)
    for p in PROTECTED_DOMAINS:
        if p.split(".")[0] in tokens:
            return p
    return None


def url_host(u: str) -> str:
    return re.sub(r"^https?://", "", u, flags=re.IGNORECASE).split("/")[0].split("?")[0].split(":")[0].lower()


def defang(s: str) -> str:
    return s.replace("http", "hxxp").replace(".", "[.]")


def domain_of(addr: str) -> str:
    _, a = parseaddr(addr or "")
    return a.split("@")[-1].lower() if "@" in a else ""


class LinkParser(HTMLParser):
    """Collects (href, visible text) pairs from HTML bodies."""

    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def parse_auth_results(msg):
    res = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for h in msg.get_all("Authentication-Results", []) or []:
        for mech in res:
            m = re.search(rf"\b{mech}=(\w+)", str(h), re.IGNORECASE)
            if m:
                res[mech] = m.group(1).lower()
    return res


def parse_received(msg):
    hops = []
    for h in msg.get_all("Received", []) or []:
        h = " ".join(str(h).split())
        ips = [ip for ip in IP_RE.findall(h) if all(0 <= int(o) <= 255 for o in ip.split("."))]
        hops.append({"header": h, "ips": ips})
    # Received headers are prepended, so the LAST one is closest to the sender.
    origin_ip = next((hop["ips"][0] for hop in reversed(hops) if hop["ips"]), None)
    return hops, origin_ip


def analyze(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    hdr = {k: str(msg.get(k, "")) for k in
           ["From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID"]}
    auth = parse_auth_results(msg)
    hops, origin_ip = parse_received(msg)

    urls, link_mismatches, attachments, body_text = set(), [], [], ""
    for part in msg.walk():
        ctype = part.get_content_type()
        fname = part.get_filename()
        if fname:
            data = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": fname,
                "content_type": ctype,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "md5": hashlib.md5(data).hexdigest(),
                "risky_extension": fname.lower().endswith(RISKY_EXT),
            })
            continue
        if ctype in ("text/plain", "text/html"):
            content = part.get_content()
            body_text += content + "\n"
            urls.update(URL_RE.findall(content))
            if ctype == "text/html":
                lp = LinkParser()
                lp.feed(content)
                for href, text in lp.links:
                    if not href:
                        continue
                    urls.add(href)
                    shown = URL_RE.search(text)
                    shown_dom = re.sub(r"^https?://", "", shown.group(0)).split("/")[0] if shown else ""
                    href_dom = re.sub(r"^https?://", "", href).split("/")[0]
                    if shown_dom and shown_dom.lower() != href_dom.lower():
                        link_mismatches.append({"display": text, "actual": href})

    from_d = domain_of(hdr["From"])
    reply_d = domain_of(hdr["Reply-To"])
    ret_d = domain_of(hdr["Return-Path"])

    flags, score = [], 0

    def flag(kind, text):
        nonlocal score
        flags.append(f"(+{WEIGHTS[kind]}) {text}")
        score += WEIGHTS[kind]

    for mech in ("spf", "dkim", "dmarc"):
        if auth[mech] != "pass":
            flag("auth", f"{mech.upper()} result is '{auth[mech]}'")
    if reply_d and reply_d != from_d:
        flag("sender_mismatch", f"Reply-To domain ({reply_d}) differs from From domain ({from_d})")
    if ret_d and ret_d != from_d:
        flag("sender_mismatch", f"Return-Path domain ({ret_d}) differs from From domain ({from_d})")
    if link_mismatches:
        flag("link_mismatch", f"{len(link_mismatches)} link(s) where display text != real destination")

    # Look-alike / brand impersonation in sender and URL domains
    for d in sorted({from_d, reply_d, ret_d} - {""}):
        target = lookalike_of(d)
        if target:
            flag("lookalike", f"Sender domain '{d}' is a look-alike of protected domain '{target}'")
    for host in sorted({url_host(u) for u in urls}):
        target = lookalike_of(host)
        if target:
            flag("lookalike", f"URL domain '{host}' is a look-alike of '{target}'")
        elif brand_in_domain(host):
            flag("brand_in_url", f"URL domain '{host}' uses our brand name but is not ours")

    # Executive impersonation from outside the org (classic BEC)
    display = (parseaddr(hdr["From"])[0] or "").lower()
    for exe in EXECUTIVES:
        if exe in display and not is_protected(from_d):
            flag("exec_impersonation",
                 f"Display name impersonates executive '{exe.title()}' from external domain {from_d}")

    for d in sorted({from_d, reply_d} & set(FREEMAIL_DOMAINS)):
        flag("freemail", f"Free-mail domain used in From/Reply-To: {d}")

    for a in attachments:
        if a["risky_extension"]:
            flag("risky_attachment", f"Risky attachment type: {a['filename']}")
    lower = (hdr["Subject"] + " " + body_text).lower()
    hits = [w for w in URGENCY_WORDS if w in lower]
    if hits:
        flag("urgency", "Urgency / pressure language: " + ", ".join(hits))

    verdict = ("LIKELY MALICIOUS" if score >= 5 else
               "SUSPICIOUS - investigate" if score >= 2 else
               "LOW RISK - verify context")

    return {
        "file": path,
        "headers": hdr,
        "authentication": auth,
        "origin_ip": origin_ip,
        "received_hops": hops,
        "urls": sorted(urls),
        "urls_defanged": sorted(defang(u) for u in urls),
        "link_mismatches": link_mismatches,
        "attachments": attachments,
        "red_flags": flags,
        "triage_score": score,
        "triage_verdict": verdict,
    }


def print_text(r):
    line = "=" * 70
    print(line)
    print(f"FILE: {r['file']}")
    print(line)
    for k, v in r["headers"].items():
        print(f"{k:<12}: {v}")
    a = r["authentication"]
    print(f"\nAuth        : SPF={a['spf']}  DKIM={a['dkim']}  DMARC={a['dmarc']}")
    print(f"Origin IP   : {r['origin_ip']}")
    print(f"\nReceived hops (sender -> recipient):")
    for i, hop in enumerate(reversed(r["received_hops"]), 1):
        print(f"  {i}. {hop['header'][:110]}")
    print("\nURLs (defanged):")
    for u in r["urls_defanged"] or ["(none)"]:
        print(f"  - {u}")
    if r["link_mismatches"]:
        print("\nLink mismatches:")
        for m in r["link_mismatches"]:
            print(f"  - shows '{m['display']}' -> goes to {defang(m['actual'])}")
    print("\nAttachments:")
    for at in r["attachments"] or [{"filename": "(none)"}]:
        if "sha256" in at:
            print(f"  - {at['filename']} ({at['content_type']}, {at['size_bytes']} B)")
            print(f"      SHA256: {at['sha256']}")
            print(f"      MD5   : {at['md5']}")
        else:
            print("  - (none)")
    print("\nRed flags:")
    for fl in r["red_flags"] or ["(none)"]:
        print(f"  [!] {fl}")
    print(f"\nTRIAGE: {r['triage_verdict']} (score {r['triage_score']})\n")


def print_md(r):
    a = r["authentication"]
    print(f"# IOC Extract - `{r['file']}`\n")
    print("| Field | Value |\n|---|---|")
    for k, v in r["headers"].items():
        print(f"| {k} | `{v}` |")
    print(f"| SPF / DKIM / DMARC | {a['spf']} / {a['dkim']} / {a['dmarc']} |")
    print(f"| Origin IP | `{r['origin_ip']}` |\n")
    print("## URLs (defanged)\n")
    for u in r["urls_defanged"] or ["(none)"]:
        print(f"- `{u}`")
    print("\n## Attachments\n")
    for at in r["attachments"]:
        print(f"- `{at['filename']}` SHA256 `{at['sha256']}`")
    if not r["attachments"]:
        print("- (none)")
    print("\n## Red Flags\n")
    for fl in r["red_flags"] or ["(none)"]:
        print(f"- {fl}")
    print(f"\n**Automated triage:** {r['triage_verdict']} (score {r['triage_score']})")
    print("\n> Automated output is a starting point. Analyst must confirm with threat intel + context.")


def main():
    ap = argparse.ArgumentParser(description="Phishing .eml triage helper")
    ap.add_argument("files", nargs="+")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true", help="JSON output")
    g.add_argument("--md", action="store_true", help="Markdown IOC table")
    args = ap.parse_args()

    results = []
    for p in args.files:
        try:
            results.append(analyze(p))
        except Exception as e:  # keep going on bad files
            print(f"[error] {p}: {e}", file=sys.stderr)
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_md(r) if args.md else print_text(r)


if __name__ == "__main__":
    main()
