import json
import unittest

import helpers  # noqa: F401
from lookout_core import analysis as A
from lookout_core import prompts as P
from lookout_core.models import record, relation


def rec(i, t, name, aliases=()):
    return record(i, t, name, description=name + " desc", aliases=aliases)


class FakeSource:
    relationships = True
    DB = {"blackcat": [rec("1", "Intrusion-Set", "ALPHV", ["BlackCat"])], "alphv": [rec("1", "Intrusion-Set", "ALPHV", ["BlackCat"])],
          "fancy bear": [rec("2", "Intrusion-Set", "APT28", ["Fancy Bear", "Sofacy"])], "apt28": [rec("2", "Intrusion-Set", "APT28", ["Fancy Bear", "Sofacy"])]}
    REL = {"1": [relation("Malware", "Cobalt Strike", "uses"), relation("Intrusion-Set", "APT28", "related-to")],
           "2": [relation("Malware", "Cobalt Strike", "uses"), relation("Attack-Pattern", "PowerShell", "uses", code="T1059.001"),
                 relation("Intrusion-Set", "ALPHV", "related-to", "inbound")]}

    def search(self, term, limit=30):
        return self.DB.get(term.lower(), []), None

    def related(self, rid, limit=80):
        return self.REL.get(rid, [])


class FakeLLM:
    def __init__(self, plan):
        self.plan = plan

    def chat(self, messages, **kw):
        return json.dumps(self.plan)


PLAN = "plan prompt"


class ContextTests(unittest.TestCase):
    def test_links_and_shared(self):
        llm = FakeLLM({"entities": [{"name": "BlackCat", "aliases": ["ALPHV"]}, {"name": "Fancy Bear", "aliases": ["APT28"]}], "intent": "links"})
        ctx = A.build_context("q", FakeSource(), llm, PLAN)
        self.assertEqual([g["asked"] for g in ctx["groups"]], ["BlackCat", "Fancy Bear"])
        self.assertEqual(ctx["direct"], [{"from": "BlackCat", "relationship": "related-to", "to": "Fancy Bear"}])   # seen from both sides, reported once
        self.assertEqual([s["name"] for s in ctx["shared"]], ["Cobalt Strike"])
        md = A.understood_markdown(ctx)
        self.assertIn("Direct links", md)
        self.assertIn("Shared connections (1)", md)

    def test_missing_and_duplicate_resolution(self):
        llm = FakeLLM({"entities": [{"name": "BlackCat"}, {"name": "ALPHV"}, {"name": "Nobody"}]})
        ctx = A.build_context("q", FakeSource(), llm, PLAN)
        self.assertEqual(len(ctx["groups"]), 1)           # two names for one record merge silently
        self.assertEqual(ctx["missing"], ["Nobody"])

    def test_source_without_relationships(self):
        src = FakeSource()
        src.relationships = False
        src.related = lambda rid, limit=80: []
        ctx = A.build_context("q", src, FakeLLM({"entities": [{"name": "BlackCat"}, {"name": "Fancy Bear"}]}), PLAN)
        self.assertFalse(ctx["relationships"])
        self.assertIn("no relationship data", A.understood_markdown(ctx))
        self.assertFalse(A.context_payload(ctx)["relationships_available"])

    def test_plan_fallbacks(self):
        self.assertEqual(A.parse_plan("not json", "what is x")["entities"], [{"name": "what is x", "aliases": []}])
        self.assertEqual(A.parse_plan("[]", "q")["entities"][0]["name"], "q")
        p = A.parse_plan(json.dumps({"entities": ["APT29", {"name": "  "}, {"name": "X", "aliases": "bad"}]}), "q")
        self.assertEqual([e["name"] for e in p["entities"]], ["APT29", "X"])

    def test_pick_prefers_exact_then_rank(self):
        rs = [record("r", "Report", "APT29 report", rank=2), record("a", "Intrusion-Set", "Cozy", aliases=["APT29"])]
        self.assertEqual(A.pick_records(rs, "apt29")[0]["id"], "a")
        self.assertEqual(A.pick_records([record("r", "Report", "R", rank=2), record("m", "Malware", "M")], "zzz")[0]["id"], "m")

    def test_context_roundtrips_through_the_client(self):
        llm = FakeLLM({"entities": [{"name": "BlackCat"}, {"name": "Fancy Bear"}]})
        ctx = A.build_context("q", FakeSource(), llm, PLAN)
        back = A.coerce_context(json.loads(json.dumps(ctx)))
        self.assertEqual(A.context_payload(back), A.context_payload(ctx))
        with self.assertRaises(ValueError):
            A.coerce_context({"groups": "x"})


class PayloadTests(unittest.TestCase):
    def test_condense_flattens_meta_and_drops_empties(self):
        r = record("1", "Vulnerability", "CVE-1", description="x" * 400, meta=[("CVSS", 9.8), ("First seen", "2024")], date="2024-02-03")
        c = A.condense(r, 50)
        self.assertEqual((c["cvss"], c["first_seen"], c["date"], len(c["description"])), ("9.8", "2024", "2024-02-03", 50))
        self.assertNotIn("aliases", c)

    def test_tlp(self):
        amber = [{"definition_type": "TLP", "definition": "TLP:AMBER"}]
        self.assertTrue(A.tlp_allowed(amber, "TLP:AMBER"))
        self.assertFalse(A.tlp_allowed(amber, "TLP:GREEN"))
        self.assertFalse(A.tlp_allowed([{"definition_type": "TLP", "definition": "TLP:CUSTOM"}], "TLP:RED"))
        with self.assertRaises(ValueError):
            A.tlp_allowed([], "TLP:PURPLE")

    def test_prompts_name_the_source(self):
        p = P.build({"label": "Security DB", "description": "relational database"})
        for k in ("plan", "recommend", "question", "entity", "bulletin"):
            self.assertIn("Security DB", p[k])
        self.assertNotIn("OpenCTI", "".join(p.values()))

    def test_prepare_bulletin_fetches_relations_and_skips_observables(self):
        src = FakeSource()
        recs = [record("o", "IPv4-Addr", "1.2.3.4", observable=True), FakeSource.DB["alphv"][0]]
        evs = list(A.prepare("bulletin", {"term": "t", "total": 2, "records": recs}, {"label": "L"}, P.build({"label": "L"}), src, "2026-10-01"))
        self.assertTrue(any("progress" in e for e in evs))
        user = evs[-1]["messages"][1]["content"]
        self.assertIn("Cobalt Strike", user)
        self.assertIn("2026-10-01", user)
        self.assertEqual(evs[-1]["num_ctx"], 12288)
        with self.assertRaises(ValueError):
            list(A.prepare("nope", {}, {"label": "L"}, {}, src, "d"))


if __name__ == "__main__":
    unittest.main()
