import unittest

import helpers
from lookout_core.sources import SourceError, create_source

HITS = {"hits": {"total": {"value": 2}, "hits": [
    {"_index": "logs-2026", "_id": "a1", "_source": {"message": "Failed login for admin", "@timestamp": "2026-09-30T01:02:03Z",
                                                      "event": {"category": "authentication", "action": "login_failed"},
                                                      "host": {"name": "web-01"}, "source.ip": "10.0.0.5", "user": {"name": ["admin", "root"]}}},
    {"_index": "logs-2026", "_id": "b2", "_source": {"message": "Odd request", "host": {"name": "web-01"}}}]}}


def handler(method, path, headers, body):
    if path.endswith("/boom/_search"):
        return 400, {"error": {"type": "parsing_exception", "reason": "bad query"}}
    if path.endswith("/_count"):
        return 200, {"count": 1234}
    if path.endswith("/_search"):
        return 200, HITS
    if "/_doc/a1" in path:
        return 200, {"found": True, "_source": HITS["hits"]["hits"][0]["_source"]}
    if "/_doc/" in path:
        return 404, {"found": False}
    if path.endswith("/boom/_search"):
        return 400, {"error": {"type": "parsing_exception", "reason": "bad query"}}
    return 500, {"error": {"reason": "unexpected"}}


class ElasticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.es = helpers.MockHTTP(handler)
        cls.cfg = {"id": "logs", "kind": "elasticsearch", "label": "Logs", "url": cls.es.url, "index": "logs-*", "api_key": "KEY123",
                   "mapping": {"name": "message", "date": "@timestamp", "type": "event.category",
                               "meta": {"Action": "event.action", "Host": "host.name"},
                               "pivots": {"Host": "host.name", "IP": "source.ip", "User": "user.name"}}}
        cls.src = create_source(cls.cfg)

    @classmethod
    def tearDownClass(cls):
        cls.es.close()

    def test_search_request_and_mapping(self):
        recs, total = self.src.search("admin login", 5)
        method, path, headers, body = self.es.requests[-1]
        self.assertEqual((method, path), ("POST", "/logs-*/_search"))
        self.assertEqual(headers["Authorization"], "ApiKey KEY123")
        q = body["query"]["simple_query_string"]
        self.assertEqual((q["query"], q["fields"], q["lenient"], body["size"]), ("admin login", ["*"], True, 5))
        self.assertIn("host.name", body["_source"]["includes"])
        r = recs[0]
        self.assertEqual((r["id"], r["type"], r["name"], r["date"], total), ("logs-2026|a1", "authentication", "Failed login for admin", "2026-09-30", 2))
        self.assertEqual({m["k"]: m["v"] for m in r["meta"]}, {"Action": "login_failed", "Host": "web-01"})
        self.assertEqual(recs[1]["type"], "Document")          # no category field, falls back to the default type

    def test_related_returns_pivot_values(self):
        rel = self.src.related("logs-2026|a1")
        got = {(r["type"], r["name"]) for r in rel}
        self.assertEqual(got, {("Host", "web-01"), ("IP", "10.0.0.5"), ("User", "admin"), ("User", "root")})
        self.assertTrue(self.src.relationships and self.src.info()["relationships"])
        self.assertEqual(self.src.related("logs-2026|zzz"), [])
        self.assertEqual(self.src.related("garbage"), [])

    def test_get_test_and_errors(self):
        self.assertEqual(self.src.get("logs-2026|a1")["name"], "Failed login for admin")
        self.assertIsNone(self.src.get("logs-2026|zzz"))
        self.assertIn("1,234 documents", self.src.test())
        bad = create_source({**self.cfg, "index": "boom"})
        with self.assertRaisesRegex(SourceError, "bad query"):
            bad.search("x")
        with self.assertRaisesRegex(SourceError, "Could not reach"):
            create_source({**self.cfg, "url": "http://127.0.0.1:1"}).test()

    def test_basic_auth_and_no_pivots(self):
        c = {"id": "x", "kind": "opensearch", "url": self.es.url, "username": "u", "password": "p"}
        s = create_source(c)
        s.search("a")
        self.assertTrue(self.es.requests[-1][2]["Authorization"].startswith("Basic "))
        self.assertFalse(s.relationships)
        self.assertEqual(s.related("logs-2026|a1"), [])


if __name__ == "__main__":
    unittest.main()
