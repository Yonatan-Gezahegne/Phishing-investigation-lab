"""Regression tests: each lab case must keep its expected triage verdict."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import eml_analyzer as ea  # noqa: E402

S = lambda name: os.path.join(ROOT, "samples", name)  # noqa: E731


class TestVerdicts(unittest.TestCase):
    def test_case01_credential_harvest_malicious(self):
        r = ea.analyze(S("case01_credential_harvest.eml"))
        self.assertEqual(r["triage_verdict"], "LIKELY MALICIOUS")
        self.assertEqual(len(r["link_mismatches"]), 1)
        self.assertTrue(any("look-alike" in f for f in r["red_flags"]))

    def test_case02_attachment_malicious(self):
        r = ea.analyze(S("case02_invoice_attachment.eml"))
        self.assertEqual(r["triage_verdict"], "LIKELY MALICIOUS")
        self.assertEqual(r["attachments"][0]["filename"], "Invoice_88213.html")
        self.assertEqual(len(r["attachments"][0]["sha256"]), 64)

    def test_case03_bec_caught_despite_auth_pass(self):
        r = ea.analyze(S("case03_bec_giftcard.eml"))
        self.assertEqual(r["authentication"], {"spf": "pass", "dkim": "pass", "dmarc": "pass"})
        self.assertEqual(r["triage_verdict"], "LIKELY MALICIOUS")

    def test_case04_benign_is_low_risk(self):
        r = ea.analyze(S("case04_benign_hr_notice.eml"))
        self.assertEqual(r["triage_score"], 0)


class TestHelpers(unittest.TestCase):
    def test_homoglyph_lookalike(self):
        self.assertEqual(ea.lookalike_of("ridgeIine-support.example"), "ridgeline.example")
        self.assertEqual(ea.lookalike_of("rldgeline.example"), "ridgeline.example")
        self.assertIsNone(ea.lookalike_of("portal.ridgeline.example"))
        self.assertIsNone(ea.lookalike_of("pinecrest-supply.example"))

    def test_defang(self):
        self.assertEqual(ea.defang("https://a.b/c"), "hxxps://a[.]b/c")

    def test_levenshtein(self):
        self.assertEqual(ea.levenshtein("ridgeline", "ridgelne"), 1)


if __name__ == "__main__":
    unittest.main()
