import unittest

import helpers  # noqa: F401
from lookout_core.sources import SourceError, create_source


def node(i, t, name, **kw):
    return {"id": i, "entity_type": t, "name": name, "description": name + " desc", "created_at": "2024-01-02T00:00:00Z", **kw}


class OpenCTITests(unittest.TestCase):
    def test_schema_fallback_then_pin(self):
        calls = []

        def transport(q):
            calls.append(q)
            if "on ThreatActorGroup" in q:
                raise ValueError({"name": "GRAPHQL_VALIDATION_FAILED", "message": 'Unknown type "ThreatActorGroup".'})
            return {"data": {"stixCoreObjects": {"pageInfo": {"globalCount": 1}, "edges": [{"node": node("9", "Malware", "X", malware_types=["ransomware"])}]}}}

        s = create_source({"id": "o", "kind": "opencti"}, transport=transport)
        recs, total = s.search('say "hi"')
        self.assertEqual((recs[0]["id"], total, s.ta), ("9", 1, "ThreatActor"))
        self.assertIn('search: "say \\"hi\\""', calls[0])                  # term is safely escaped
        n = len(calls)
        s.search("again")
        self.assertEqual(len(calls), n + 1)                                  # schema variant is pinned

    def test_non_schema_errors_pass_through(self):
        def transport(q):
            raise ValueError({"name": "Unauthorized", "message": "bad token"})
        with self.assertRaises(ValueError):
            create_source({"id": "o", "kind": "opencti"}, transport=transport).search("x")

    def test_record_mapping(self):
        def transport(q):
            return {"data": {"stixCoreObjects": {"pageInfo": {"globalCount": 3}, "edges": [
                {"node": node("1", "Vulnerability", "CVE-1", x_opencti_cvss_base_score=9.8, objectLabel=[{"value": "kev"}])},
                {"node": node("2", "Attack-Pattern", "PowerShell", x_mitre_id="T1059.001")},
                {"node": {"id": "3", "entity_type": "IPv4-Addr", "observable_value": "1.2.3.4", "created_at": "2024-01-01T00:00:00Z"}}]}}}
        recs, _ = create_source({"id": "o", "kind": "opencti"}, transport=transport).search("x")
        self.assertEqual({m["k"]: m["v"] for m in recs[0]["meta"]}, {"CVSS": "9.8"})
        self.assertEqual((recs[0]["labels"], recs[0]["date_label"]), (["kev"], "Added"))
        self.assertEqual({m["k"]: m["v"] for m in recs[1]["meta"]}, {"MITRE ID": "T1059.001"})
        self.assertEqual((recs[2]["name"], recs[2]["observable"], recs[2]["rank"]), ("1.2.3.4", True, 3))

    def test_related_directions(self):
        def transport(q):
            e = lambda rel, n: {"node": {"relationship_type": rel, "to": n, "from": n}}
            return {"data": {"out": {"edges": [e("uses", {"entity_type": "Malware", "name": "Cobalt Strike"})]},
                             "inc": {"edges": [e("attributed-to", {"entity_type": "Intrusion-Set", "name": "APT28"}), e("x", None)]}}}
        rel = create_source({"id": "o", "kind": "opencti"}, transport=transport).related("abc")
        self.assertEqual([(r["name"], r["dir"], r["rel"]) for r in rel], [("Cobalt Strike", "outbound", "uses"), ("APT28", "inbound", "attributed-to")])

    def test_no_data_means_no_access(self):
        s = create_source({"id": "o", "kind": "opencti"}, transport=lambda q: None)
        with self.assertRaisesRegex(SourceError, "no data"):
            s.search("x")

    def test_unknown_kind(self):
        with self.assertRaisesRegex(SourceError, "unknown kind"):
            create_source({"id": "o", "kind": "oracle"})


if __name__ == "__main__":
    unittest.main()
