# Incident Report: PHISH-2026-004 Reported HR Email (False Positive)

| Field | Value |
|---|---|
| **Case ID** | PHISH-2026-004 |
| **Analyst** | Yonatan Gezahegne |
| **Date reported** | 2026-09-17 |
| **Reported by** | Employee (after company-wide phishing awareness following PHISH-2026-001) |
| **Classification** | **Benign**: legitimate internal communication |
| **Severity** | Informational |
| **Status** | Closed, no action |

## 1. Executive Summary

An employee reported an "open enrollment" email with a link to a benefits portal. Verification showed it is a legitimate HR communication sent through Ridgeline's internal relay with full authentication, linking only to a Ridgeline-owned domain. Closed as benign. The reporter was thanked, since reporting after a real incident is the behavior we want.

## 2. Initial Evidence

- **Subject:** `Open enrollment reminder - benefits portal now open`
- **Sender:** `Ridgeline HR` / `hr-notifications@ridgeline.example`
- **Reply-To / Return-Path:** `hr@ridgeline.example` / `hr-notifications@ridgeline.example` (same organization domain)
- **Recipients:** all-staff@ridgeline.example
- **SPF / DKIM / DMARC:** pass / pass / pass for **`ridgeline.example`** (our own domain)
- **Originating host:** `internal-relay.ridgeline.example` (`192.0.2.25`), a single internal hop
- **URL:** `https://benefits.ridgeline.example/enroll`, a subdomain of our protected domain

## 3. Verification Steps

1. **Authentication:** all passed **for our own domain**. Unlike PHISH-2026-003, the passing domain is `ridgeline.example`.
2. **Routing:** single `Received` hop from our internal relay; the email never came from outside.
3. **Links:** the one URL points to a Ridgeline subdomain; display text matches destination.
4. **Content/context:** open enrollment in mid/late September is expected. No credential request, no urgency threats, no attachments.
5. **Automated triage:** `eml_analyzer.py` score 0 (LOW RISK), consistent with manual review.
6. **Out-of-band confirmation (production step):** confirm with HR that they sent the campaign.

## 4. Why It Looked Suspicious (and why it wasn't)

| Reporter's concern | Finding |
|---|---|
| "Asks me to click a link to log in" | Link goes to `benefits.ridgeline.example`, our domain |
| "Came right after the password phish" | Timing is coincidental; routing and auth are internal |
| "Sent to everyone" | Normal for all-staff HR announcements |

## 5. Actions

- [x] Closed as benign; no containment needed
- [x] Replied to reporter: thanked them and explained what made it legitimate (sender domain, link domain)
- [ ] Suggest HR pre-announce major email campaigns on the intranet to reduce false positives

## 6. Lesson

Fast, well-documented false-positive closure matters as much as catching real threats: it keeps queue time down and reinforces reporting without making employees feel foolish.
