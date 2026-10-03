import copy
import json
import os
import unittest

import helpers  # noqa: F401
from lookout_core.sources import SourceError, create_source

ROOT = os.path.join(os.path.dirname(__file__), "..", "examples")
FIXTURE = os.path.join(ROOT, "qsirch_synthetic.json")
MAPPING = {"id": "id", "name": "filename", "path": "path", "size": "size", "modified": "modified", "indexed": "indexed", "taken": "taken",
           "category": "category", "snippet": "snippet", "tags": "tags", "people": "people", "objects": "objects", "places": "places",
           "ocr": "ocr", "summary": "summary", "transcript": "transcript"}


def cfg(**kw):
    c = {"id": "files", "kind": "qsirch", "label": "NAS files", "backend": "fixture", "fixture": FIXTURE, "mapping": dict(MAPPING),
         "content": {"path_map": [{"remote": "/share/Evidence", "local": os.path.join(ROOT, "evidence")}]}}
    c.update(kw)
    return c


class QsirchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = create_source(cfg())

    def test_mapping_of_documents_photos_and_video(self):
        recs, total = self.src.search("203.0.113.50")
        by = {r["name"]: r for r in recs}
        self.assertEqual(set(by), {"incident-notes.txt", "whiteboard.jpg"})
        doc, photo = by["incident-notes.txt"], by["whiteboard.jpg"]
        self.assertEqual((doc["type"], doc["evidence"].get("ai_derived", [])), ("Document", []))
        self.assertEqual((photo["type"], photo["date_label"], photo["date"]), ("Photo", "Taken", "2026-09-29"))
        self.assertEqual(photo["evidence"]["ai_derived"], ["ocr", "summary"])
        self.assertIn("beacon every 60s", photo["description"])          # no snippet, so OCR text stands in
        self.assertEqual(photo["evidence"]["path"], "/share/Evidence/case-001/whiteboard.jpg")
        self.assertIn({"k": "Size", "v": "2.4 MB"}, photo["meta"])
        self.assertEqual(set(photo["labels"]), {"case-001", "whiteboard", "diagram"})
        video = self.src.get("f4")
        self.assertEqual((video["type"], video["evidence"]["ai_derived"]), ("Video", ["summary", "transcript"]))

    def test_relations_are_pivots(self):
        rel = {(r["type"], r["name"]) for r in self.src.related("f3")}
        self.assertEqual(rel, {("Person", "Alex"), ("Tag", "case-001"), ("Tag", "whiteboard"), ("Object", "whiteboard"),
                               ("Object", "diagram"), ("Place", "Meeting room"), ("Folder", "/share/Evidence/case-001")})
        self.assertEqual(self.src.related("nope"), [])

    def test_filters_are_applied_when_the_backend_cannot(self):
        photos, _ = self.src.search("case-001", filters={"category": "photo"})
        self.assertEqual([r["name"] for r in photos], ["whiteboard.jpg"])
        recent, _ = self.src.search("case-001", filters={"date_from": "2026-09-30"})
        self.assertEqual({r["name"] for r in recent}, {"incident-notes.txt", "mail-2026-09-30.eml"})
        folder, _ = self.src.search("case", filters={"path_contains": "case-002"})
        self.assertEqual([r["name"] for r in folder], ["lobby-camera.mp4"])
        ignored, _ = self.src.search("case-001", filters={"colour": "red", "category": ""})
        self.assertEqual(len(ignored), 3)

    def test_test_reports_fixture_and_capabilities(self):
        msg = self.src.test()
        self.assertIn("sample data", msg)
        self.assertIn("ocr", msg)
        self.assertTrue(self.src.info()["evidence"])
        self.assertEqual(self.src.info()["filters"], ["category", "date_from", "date_to", "path_contains"])

    def test_evidence_through_mounted_share(self):
        rec = self.src.get("f1")
        facts = self.src.content.verify(rec["evidence"]["path"])
        self.assertEqual(len(facts["sha256"]), 64)
        self.assertIn("203.0.113.50", self.src.content.text(rec["evidence"]["path"])["text"])

    def test_http_backend_reports_it_is_waiting_for_the_api_reference(self):
        s = create_source(cfg(backend="http"))
        for call in (s.test, lambda: s.search("x"), lambda: s.get("1")):
            with self.assertRaisesRegex(SourceError, "waiting for the Qsirch API reference"):
                call()

    def test_config_validation(self):
        bad = cfg()
        bad["mapping"] = {}
        with self.assertRaisesRegex(SourceError, "mapping"):
            create_source(bad)
        with self.assertRaisesRegex(SourceError, "fixture"):
            create_source(cfg(fixture=""))
        with self.assertRaisesRegex(SourceError, "backend"):
            create_source(cfg(backend="carrier-pigeon"))
        with self.assertRaisesRegex(SourceError, "Could not read the fixture"):
            create_source(cfg(fixture="/nonexistent.json"))


if __name__ == "__main__":
    unittest.main()
