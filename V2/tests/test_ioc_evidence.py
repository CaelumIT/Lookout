import os
import tempfile
import unittest
import zipfile

import helpers  # noqa: F401
from lookout_core import ioc as IOC
from lookout_core.evidence import ContentAccess, EvidenceError, extract_text


def vals(text, **kw):
    return {(i["kind"], i["value"]) for i in IOC.extract(text, **kw)}


class IocTests(unittest.TestCase):
    def test_common_kinds(self):
        got = vals("Beacon to 203.0.113.50 and evil.example.com; CVE-2024-3400, T1059.001, md5 44d88612fea8a8f36de82e1278abb02f")
        self.assertEqual(got, {("ipv4", "203.0.113.50"), ("domain", "evil.example.com"), ("cve", "CVE-2024-3400"),
                               ("technique", "T1059.001"), ("md5", "44d88612fea8a8f36de82e1278abb02f")})

    def test_defanged_text_is_refanged(self):
        got = vals("hxxps://evil-update[.]example[.]com/login and admin[at]example[.]org from 203[.]0[.]113[.]9")
        self.assertIn(("url", "https://evil-update.example.com/login"), got)
        self.assertIn(("domain", "evil-update.example.com"), got)
        self.assertIn(("email", "admin@example.org"), got)
        self.assertIn(("ipv4", "203.0.113.9"), got)

    def test_false_positives_are_avoided(self):
        got = vals("Open report.pdf, run setup.exe, see v1.2.3.4.5 and 999.1.1.1, time 10:30:15, e.g. this")
        self.assertEqual(got, set())

    def test_urls_do_not_leak_path_fragments_as_domains(self):
        got = vals("http://example.com/files/payload.php?x=1")
        self.assertEqual(got, {("url", "http://example.com/files/payload.php?x=1"), ("domain", "example.com")})

    def test_hash_kinds_by_length_and_no_partial_matches(self):
        sha256 = "a" * 64
        got = vals(f"{sha256} {'b' * 40} {'c' * 32} {'d' * 33}")
        self.assertEqual(got, {("sha256", sha256), ("sha1", "b" * 40), ("md5", "c" * 32)})

    def test_ipv6_validated_dedupe_order_and_limits(self):
        got = IOC.extract("2001:db8::1 and 2001:db8:0:0:0:0:0:1 and 203.0.113.1 203.0.113.1")
        self.assertEqual([i["value"] for i in got if i["kind"] == "ipv4"], ["203.0.113.1"])
        self.assertTrue(any(i["kind"] == "ipv6" for i in got))
        self.assertEqual(len(IOC.extract(" ".join(f"10.0.0.{i}" for i in range(60)), max_items=5)), 5)
        self.assertEqual(vals("203.0.113.1 evil.example.com", kinds=["ipv4"]), {("ipv4", "203.0.113.1")})
        self.assertEqual(IOC.extract(""), [])

    def test_helpers(self):
        self.assertEqual(IOC.search_term({"kind": "url", "value": "https://evil.example.com/a"}), "evil.example.com")
        self.assertEqual(IOC.search_term({"kind": "ipv4", "value": "1.2.3.4"}), "1.2.3.4")
        self.assertEqual(IOC.defang("https://evil.example.com"), "hxxps://evil[.]example[.]com")


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.root, "case"))
        self.f = os.path.join(self.root, "case", "a.txt")
        with open(self.f, "w") as fh:
            fh.write("hello evidence\nsecond line 203.0.113.5")
        self.access = ContentAccess([{"remote": "/share/Evidence", "local": self.root}], max_text_chars=20)

    def test_path_mapping_and_hash(self):
        facts = self.access.verify("/share/Evidence/case/a.txt")
        import hashlib
        with open(self.f, "rb") as fh:
            self.assertEqual(facts["sha256"], hashlib.sha256(fh.read()).hexdigest())
        self.assertEqual((facts["size"], facts["stable"]), (os.path.getsize(self.f), True))
        self.assertTrue(facts["modified"].endswith("Z"))
        self.assertNotIn("sha256", self.access.verify("/share/Evidence/case/a.txt", want_hash=False))

    def test_traversal_and_symlink_escape_are_refused(self):
        for bad in ["/share/Evidence/../etc/passwd", "/share/Other/a.txt", "/etc/passwd", "/share/Evidence/case/../../x", "\\share\\Evidence\\..\\..\\x"]:
            with self.assertRaises(EvidenceError, msg=bad):
                self.access.facts(bad)
        outside = tempfile.mkdtemp()
        with open(os.path.join(outside, "secret.txt"), "w") as fh:
            fh.write("x")
        os.symlink(outside, os.path.join(self.root, "link"))
        with self.assertRaisesRegex(EvidenceError, "outside"):
            self.access.facts("/share/Evidence/link/secret.txt")

    def test_missing_directory_and_size_limit(self):
        with self.assertRaisesRegex(EvidenceError, "not found"):
            self.access.facts("/share/Evidence/case/nope.txt")
        with self.assertRaisesRegex(EvidenceError, "not a regular file"):
            self.access.facts("/share/Evidence/case")
        small = ContentAccess([{"remote": "/share/Evidence", "local": self.root}], max_hash_bytes=3)
        with self.assertRaisesRegex(EvidenceError, "hashing limit"):
            small.verify("/share/Evidence/case/a.txt")

    def test_text_extraction(self):
        t = self.access.text("/share/Evidence/case/a.txt")
        self.assertEqual((len(t["text"]), t["truncated"]), (20, True))
        eml = os.path.join(self.root, "m.eml")
        with open(eml, "w") as fh:
            fh.write("From: a@example.com\nSubject: Hi\nContent-Type: text/plain\n\nBody with 203.0.113.7\n")
        self.assertIn("Body with 203.0.113.7", extract_text(eml)["text"])
        self.assertIn("Subject: Hi", extract_text(eml)["text"])
        docx = os.path.join(self.root, "d.docx")
        with zipfile.ZipFile(docx, "w") as z:
            z.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
                       '<w:p><w:r><w:t>First para</w:t></w:r></w:p><w:p><w:r><w:t>Second</w:t></w:r></w:p></w:body></w:document>')
        self.assertEqual(extract_text(docx)["text"], "First para\nSecond")
        bad = os.path.join(self.root, "bad.docx")
        with open(bad, "w") as fh:
            fh.write("not a zip")
        with self.assertRaises(EvidenceError):
            extract_text(bad)
        pic = os.path.join(self.root, "p.jpg")
        with open(pic, "wb") as fh:
            fh.write(b"\xff\xd8")
        self.assertIsNone(extract_text(pic))

    def test_config_validation(self):
        self.assertIsNone(ContentAccess.from_cfg(None))
        for bad in [{"path_map": []}, {"path_map": [{"remote": "relative", "local": "/x"}]}, {"path_map": [{"remote": "/a"}]}]:
            with self.assertRaises(EvidenceError):
                ContentAccess.from_cfg(bad)


if __name__ == "__main__":
    unittest.main()
