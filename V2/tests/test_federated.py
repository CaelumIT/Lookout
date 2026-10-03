import json
import os
import unittest

import helpers
from lookout_core import analysis as A
from lookout_core import prompts as P
from lookout_core.federated import Federation
from lookout_core.sources import SourceError, create_sources

ROOT = os.path.join(os.path.dirname(__file__), "..", "examples")


class Plan:
    def __init__(self, plan):
        self.plan = plan

    def chat(self, messages, **kw):
        return json.dumps(self.plan)


def build(extra_error=False):
    """An 'intel' source (SQLite standing in for a threat platform) plus a file index (Qsirch sample data)."""
    import sqlite3
    path = os.path.join(os.path.dirname(helpers.make_sqlite()), "intel.db")
    db = sqlite3.connect(path)
    db.executescript("""
    CREATE TABLE actors(id INTEGER PRIMARY KEY, name TEXT, about TEXT);
    CREATE TABLE infra(actor_id INTEGER, value TEXT, kind TEXT);
    INSERT INTO actors VALUES (1,'APT-Example','Operates C2 at 203.0.113.50 and the domain evil-update.example.com'),(2,'Other Group','Unrelated');
    INSERT INTO infra VALUES (1,'203.0.113.50','IPv4-Addr'),(1,'evil-update.example.com','Domain-Name'),(2,'198.51.100.7','IPv4-Addr');
    """)
    db.commit()
    db.close()
    cfgs = [{"id": "intel", "kind": "sqlite", "label": "Intel DB", "path": path,
             "entities": [{"table": "actors", "type": "Intrusion-Set", "id": "id", "name": "name", "description": "about", "search": ["name", "about"]}],
             "relations": [{"entity": "Intrusion-Set", "rel": "uses", "sql": "SELECT value AS name, kind AS type FROM infra WHERE actor_id = :id"}]},
            {"id": "files", "kind": "qsirch", "label": "NAS files", "backend": "fixture", "fixture": os.path.join(ROOT, "qsirch_synthetic.json"),
             "mapping": {"id": "id", "name": "filename", "path": "path", "modified": "modified", "category": "category", "snippet": "snippet",
                         "tags": "tags", "ocr": "ocr", "summary": "summary", "transcript": "transcript", "places": "places"}}]
    if extra_error:
        cfgs.append({"id": "broken", "kind": "qsirch", "label": "Broken", "backend": "http", "mapping": {"id": "id", "name": "n"}})
    return Federation(create_sources(cfgs))


class FederationTests(unittest.TestCase):
    def test_search_all_tags_interleaves_and_isolates_failures(self):
        fed = build(extra_error=True)
        r = fed.search_all("203.0.113.50", 10)
        self.assertEqual({x["source"] for x in r["records"]}, {"intel", "files"})
        self.assertTrue(all(x["source_label"] for x in r["records"]))
        self.assertIn("broken", r["errors"])
        self.assertIn("waiting for the Qsirch API reference", r["errors"]["broken"])
        self.assertEqual(r["counts"]["broken"], 0)
        self.assertEqual(r["records"][0]["source"], "intel")                 # round-robin, not one source first
        with self.assertRaises(SourceError):
            Federation({k: v for k, v in build(True).sources.items() if k == "broken"}).search("x")

    def test_test_summarises_sources(self):
        self.assertIn("2 of 2", build().test())
        self.assertIn("2 of 3", build(True).test())

    def test_filters_only_reach_sources_that_support_them(self):
        fed = build()
        r = fed.search_all("case", 10, filters={"category": "video"})
        self.assertEqual([x["name"] for x in r["records"]], ["lobby-camera.mp4"])
        self.assertEqual(fed.filter_keys, ("category", "date_from", "date_to", "path_contains"))

    def test_pivot_finds_files_that_mention_an_indicator_from_the_intel_source(self):
        fed = build()
        recs, _ = fed.sources["intel"].search("APT-Example")
        for r in recs:
            r["source"], r["source_label"] = "intel", "Intel DB"
        group = {"asked": "APT-Example", "records": recs, "exact": True, "related": [{**x, "source": "intel"} for x in fed.sources["intel"].related(recs[0]["id"])]}
        pivots = fed.pivot([group])
        by = {p["ioc"]["value"]: p for p in pivots}
        self.assertIn("203.0.113.50", by)
        self.assertEqual({h["name"] for h in by["203.0.113.50"]["hits"]}, {"incident-notes.txt", "whiteboard.jpg"})
        self.assertEqual(by["203.0.113.50"]["origin_sources"], ["intel"])
        self.assertTrue(all(h["source"] == "files" for h in by["203.0.113.50"]["hits"]))   # never searches the source it came from
        self.assertIn("evil-update.example.com", by)
        self.assertNotIn("198.51.100.7", by)                                              # belongs to another actor


class FederatedContextTests(unittest.TestCase):
    def test_question_across_sources_with_pivots(self):
        fed = build()
        prompts = P.build(fed.info())
        plan = Plan({"entities": [{"name": "APT-Example"}], "intent": "overview"})
        ctx = A.build_context("What do we know about APT-Example?", fed, plan, prompts["plan"])
        self.assertTrue(ctx["federated"])
        self.assertEqual(ctx["groups"][0]["records"][0]["source"], "intel")
        self.assertTrue(ctx["pivots"])
        md = A.understood_markdown(ctx)
        self.assertIn("Indicators that appear in other sources", md)
        self.assertIn("incident-notes.txt (NAS files)", md)
        self.assertIn("leads, not proof", md)
        payload = A.context_payload(ctx)
        self.assertIn("pivots", payload)
        self.assertEqual(payload["entities"][0]["records"][0]["source"], "Intel DB")
        back = A.coerce_context(json.loads(json.dumps(ctx)))                              # survives the browser round trip
        self.assertEqual(A.context_payload(back), payload)
        self.assertGreaterEqual(len(A.context_records(back)), 3)

    def test_planner_filters_reach_only_capable_sources(self):
        fed = build()
        plan = Plan({"entities": [{"name": "case-001"}], "filters": {"category": "photo", "date_from": "not-a-date", "colour": "red"}})
        ctx = A.build_context("photos of case-001", fed, plan, "p")
        self.assertEqual(ctx["filters"], {"category": "photo"})
        self.assertEqual([r["name"] for g in ctx["groups"] for r in g["records"]], ["whiteboard.jpg"])
        self.assertIn("category = photo", A.understood_markdown(ctx))

    def test_prompts_carry_evidence_rules_and_filter_hints(self):
        fed = build()
        p = P.build(fed.info())
        for k in ("recommend", "question", "entity", "bulletin"):
            self.assertIn("machine-generated", p[k])
            self.assertIn("pivots", p[k])
        self.assertIn("path_contains", p["plan"])
        self.assertNotIn("filters", P.build({"label": "X", "description": ""})["plan"])


class AppendixTests(unittest.TestCase):
    def test_lists_files_with_hash_status_and_ai_flags(self):
        fed = build()
        recs = fed.search_all("whiteboard", 5)["records"]
        wb = next(r for r in recs if r["name"] == "whiteboard.jpg")
        none = A.evidence_appendix([wb])
        self.assertIn("SHA-256 not verified", none)
        self.assertIn("machine-generated text: ocr, summary", none)
        self.assertIn("/share/Evidence/case-001/whiteboard.jpg", none)
        done = A.evidence_appendix([wb, wb], {("files", wb["id"]): {"sha256": "ab" * 32, "hashed_at": "2026-10-01T00:00:00Z", "stable": False}})
        self.assertIn("ab" * 32, done)
        self.assertIn("the file changed while being read", done)
        self.assertEqual(done.count("**whiteboard.jpg**"), 1)                                  # de-duplicated
        self.assertEqual(A.evidence_appendix([{"id": "x", "name": "n", "evidence": None}]), "")


if __name__ == "__main__":
    unittest.main()
