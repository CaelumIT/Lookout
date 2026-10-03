import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import helpers

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))
import server as S  # noqa: E402


def ollama_handler(method, path, headers, body):
    if path == "/api/tags":
        return 200, {"models": [{"name": "tiny:1b"}]}
    if body and not body.get("stream"):        # question parsing
        return 200, {"message": {"content": json.dumps({"entities": [{"name": "Phishing campaign"}, {"name": "Ransomware on FIN-01"}], "intent": "links"})}}
    return 200, [{"message": {"content": "## Summary\n"}}, {"message": {"content": "Hello.\n## Suggested searches\n- FIN-01\n"}}, {"done": True}]


EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


class FederatedServerTests(unittest.TestCase):
    """Two sources (SQLite + sample Qsirch data), evidence access through a mapped folder."""

    @classmethod
    def setUpClass(cls):
        cls.llm = helpers.MockHTTP(ollama_handler)
        cls.hits = []
        files = {"id": "files", "kind": "qsirch", "label": "NAS files", "backend": "fixture", "fixture": os.path.join(EXAMPLES, "qsirch_synthetic.json"),
                 "mapping": {"id": "id", "name": "filename", "path": "path", "size": "size", "modified": "modified", "indexed": "indexed",
                             "category": "category", "snippet": "snippet", "tags": "tags", "ocr": "ocr", "summary": "summary"},
                 "content": {"path_map": [{"remote": "/share/Evidence", "local": os.path.join(EXAMPLES, "evidence")}]}}
        cfg = {"server": {}, "ollama": {"url": cls.llm.url, "timeout": 10, "default_model": "tiny:1b"},
               "sources": [helpers.sql_cfg(helpers.make_sqlite()), files]}
        S.Handler.app = cls.app = S.App(cfg)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
        cls.httpd.daemon_threads = True
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.llm.close()

    def call(self, path, body=None, headers=None, raw=None):
        return ServerTests.call(self, path, body, headers, raw)

    def test_sources_list_ends_with_the_federation(self):
        st, j = self.call("/api/sources")
        self.assertEqual([s["id"] for s in j["sources"]], ["secdb", "files", "*"])
        self.assertTrue(j["sources"][2]["evidence"])
        self.assertNotIn("examples/", json.dumps(j))                  # local folders are not disclosed

    def test_federated_search_tags_records_and_reports_errors(self):
        st, j = self.call("/api/search", {"source": "*", "term": "case-001"})
        self.assertEqual(st, 200)
        self.assertEqual({r["source"] for r in j["records"]}, {"files"})
        st, j = self.call("/api/search", {"source": "*", "term": "ransomware"})
        self.assertEqual({r["source"] for r in j["records"]}, {"secdb"})
        st, j = self.call("/api/search", {"source": "files", "term": "whiteboard", "filters": {"category": "photo", "bogus": "x"}})
        self.assertEqual([r["name"] for r in j["records"]], ["whiteboard.jpg"])
        self.assertEqual(j["records"][0]["source"], "files")

    def test_related_needs_a_concrete_source(self):
        self.assertEqual(self.call("/api/related", {"source": "*", "id": "x"})[0], 400)
        st, j = self.call("/api/related", {"source": "files", "id": "f3"})
        self.assertTrue(any(i["type"] == "Folder" for i in j["items"]))

    def test_iocs_endpoint(self):
        st, j = self.call("/api/iocs", {"text": "see hxxp://evil[.]example[.]com and 203.0.113.50"})
        self.assertEqual({(i["kind"], i["value"]) for i in j["iocs"]}, {("url", "http://evil.example.com"), ("domain", "evil.example.com"), ("ipv4", "203.0.113.50")})
        st, j = self.call("/api/iocs", {"record": {"id": "1", "type": "t", "name": "C2 at 203.0.113.50", "description": ""}})
        self.assertEqual([i["value"] for i in j["iocs"]], ["203.0.113.50"])
        self.assertEqual(self.call("/api/iocs", {"record": "bad"})[0], 400)

    def test_evidence_hashes_a_file_whose_path_comes_from_the_source(self):
        st, j = self.call("/api/evidence", {"source": "files", "id": "f1", "hash": True, "text": True})
        self.assertEqual(st, 200)
        self.assertEqual(len(j["facts"]["sha256"]), 64)
        self.assertTrue(j["facts"]["stable"])
        self.assertIn("203.0.113.50", {i["value"] for i in j["iocs"]})
        self.assertIn("Case 001 working notes", j["text"]["text"])
        self.assertIn(("files", "f1"), self.app.hashes)
        # a path supplied by the browser is ignored; only the record id matters
        st, j2 = self.call("/api/evidence", {"source": "files", "id": "f1", "path": "/etc/passwd"})
        self.assertEqual(j2["facts"]["path"], "/share/Evidence/case-001/incident-notes.txt")

    def test_evidence_errors_are_clean(self):
        self.assertEqual(self.call("/api/evidence", {"source": "secdb", "id": "incidents:1"})[0], 400)      # no content section
        st, j = self.call("/api/evidence", {"source": "files", "id": "f3"})                                    # indexed, but not in the sample folder
        self.assertEqual(st, 400)
        self.assertIn("not found", j["error"])
        self.assertEqual(self.call("/api/evidence", {"source": "files", "id": "nope"})[0], 404)
        self.assertEqual(self.call("/api/evidence", {"source": "*", "id": "f1"})[0], 400)

    def test_federated_contextual_and_bulletin_with_appendix(self):
        self.call("/api/evidence", {"source": "files", "id": "f1", "hash": True})
        st, evs = self.call("/api/contextual", {"source": "*", "question": "what do we have on the phishing campaign", "model": "tiny:1b"})
        self.assertEqual(st, 200)
        ctx = evs[-1]["context"]
        self.assertTrue(ctx["federated"])
        recs = [r for g in ctx["groups"] for r in g["records"]]
        self.assertTrue(recs and all(r.get("source") for r in recs))
        pool = self.call("/api/search", {"source": "files", "term": "case-001"})[1]["records"]
        st, evs = self.call("/api/generate", {"source": "*", "kind": "bulletin", "term": "case-001", "total": len(pool), "records": pool, "model": "tiny:1b"})
        self.assertEqual(st, 200)
        text = "".join(e.get("token", "") for e in evs)
        self.assertIn("## Evidence appendix", text)
        self.assertIn("incident-notes.txt", text)
        sha = self.app.hashes[("files", "f1")]["sha256"]
        self.assertIn(sha, text)                                            # the verified file shows its hash
        self.assertIn("SHA-256 not verified", text)                         # the others do not
        sent = self.llm.requests[-1][3]["messages"][0]["content"]
        self.assertIn("NAS files", sent)
        self.assertIn("machine-generated", sent)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.llm = helpers.MockHTTP(ollama_handler)
        cfg = {"server": {}, "ollama": {"url": cls.llm.url, "timeout": 10, "default_model": "tiny:1b"},
               "sources": [helpers.sql_cfg(helpers.make_sqlite(), description="Our SOC incident log")]}
        S.Handler.app = S.App(cfg)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), S.Handler)
        cls.httpd.daemon_threads = True
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.llm.close()

    def call(self, path, body=None, headers=None, raw=None):
        data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        req = urllib.request.Request(self.base + path, data=data, headers={"Content-Type": "application/json", **(headers or {})},
                                     method="GET" if data is None else "POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                text = r.read().decode()
                return r.status, ([json.loads(l) for l in text.splitlines() if l.strip()] if "ndjson" in r.headers["Content-Type"] else json.loads(text))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_sources_do_not_leak_config(self):
        st, j = self.call("/api/sources")
        self.assertEqual(st, 200)
        s = j["sources"][0]
        self.assertEqual((s["id"], s["label"], s["relationships"]), ("secdb", "Security DB", True))
        self.assertIn("Our SOC incident log", s["description"])
        self.assertNotIn(".db", json.dumps(j))            # the database path never reaches the browser
        self.assertEqual(j["default_model"], "tiny:1b")

    def test_search_related_test_models(self):
        st, j = self.call("/api/search", {"source": "secdb", "term": "ransomware"})
        self.assertEqual((st, j["records"][0]["id"], j["total"]), (200, "incidents:1", 1))
        st, j = self.call("/api/related", {"source": "secdb", "id": "incidents:2"})
        self.assertEqual(sorted(i["name"] for i in j["items"]), ["FIN-01", "HR-02"])
        self.assertTrue(self.call("/api/test", {"source": "secdb"})[1]["ok"])
        self.assertEqual(self.call("/api/models")[1], {"models": ["tiny:1b"]})

    def test_errors(self):
        self.assertEqual(self.call("/api/search", {"source": "nope", "term": "x"})[0], 404)
        self.assertEqual(self.call("/api/search", {"source": "secdb", "term": " "})[0], 400)
        self.assertEqual(self.call("/api/search", raw=b"{not json")[0], 400)
        self.assertEqual(self.call("/api/generate", {"source": "secdb", "kind": "recommend", "records": ["bad"]})[0], 400)
        self.assertEqual(self.call("/api/contextual", {"source": "secdb", "question": ""})[0], 400)
        self.assertEqual(self.call("/api/nothing", {})[0], 404)

    def test_guards(self):
        self.assertEqual(self.call("/api/sources", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.call("/api/sources", headers={"Origin": "http://evil.example"})[0], 403)

    def test_contextual_then_generate(self):
        st, evs = self.call("/api/contextual", {"source": "secdb", "question": "links between the phishing campaign and the ransomware", "model": "tiny:1b"})
        self.assertEqual(st, 200)
        self.assertTrue(any("progress" in e for e in evs))
        ctx = evs[-1]["context"]
        self.assertEqual([g["asked"] for g in ctx["groups"]], ["Phishing campaign", "Ransomware on FIN-01"])
        self.assertEqual([s["name"] for s in ctx["shared"]], ["FIN-01"])      # both incidents affect FIN-01
        self.assertEqual(ctx["direct"], [])

        before = len(self.llm.requests)
        st, evs = self.call("/api/generate", {"source": "secdb", "kind": "recommend", "term": "q", "total": 2, "model": "tiny:1b",
                                              "records": [r for g in ctx["groups"] for r in g["records"]], "context": ctx})
        self.assertEqual(st, 200)
        self.assertEqual("".join(e.get("token", "") for e in evs), "## Summary\nHello.\n## Suggested searches\n- FIN-01\n")
        self.assertTrue(evs[-1].get("done"))
        sent = self.llm.requests[before][3]
        self.assertEqual(sent["model"], "tiny:1b")
        self.assertIn("Security DB", sent["messages"][0]["content"])
        self.assertIn("shared_connections", sent["messages"][1]["content"])
        self.assertIn("FIN-01", sent["messages"][1]["content"])

    def test_generate_bulletin_from_simple_search(self):
        st, j = self.call("/api/search", {"source": "secdb", "term": "campaign"})
        st, evs = self.call("/api/generate", {"source": "secdb", "kind": "bulletin", "term": "campaign", "total": j["total"], "records": j["records"], "model": "tiny:1b"})
        self.assertEqual(st, 200)
        self.assertTrue(any("progress" in e for e in evs))
        self.assertTrue(any(e.get("token") for e in evs))
        user = self.llm.requests[-1][3]["messages"][1]["content"]
        self.assertIn("HR-02", user)         # relations were fetched server-side for the bulletin

    def test_no_model_is_a_clean_error(self):
        S.Handler.app.ollama.model = None
        try:
            st, j = self.call("/api/generate", {"source": "secdb", "kind": "recommend", "term": "q", "records": []})
            self.assertEqual(st, 502)       # reported as a normal HTTP error before streaming starts
            self.assertIn("No model selected", j["error"])
        finally:
            S.Handler.app.ollama.model = "tiny:1b"


if __name__ == "__main__":
    unittest.main()
