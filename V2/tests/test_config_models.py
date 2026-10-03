import unittest

import helpers  # noqa: F401
from lookout_core import config as C
from lookout_core.models import coerce_record, record


class ConfigTests(unittest.TestCase):
    def test_env_expansion_and_defaults(self):
        cfg = C.parse({"sources": [{"id": "a", "kind": "sqlite", "token": "${T}"}]}, env={"T": "secret"})
        self.assertEqual(cfg["sources"][0]["token"], "secret")
        self.assertEqual(cfg["ollama"]["url"], "http://localhost:11434")

    def test_missing_env_var_names_the_variable(self):
        with self.assertRaisesRegex(C.ConfigError, "NOPE"):
            C.parse({"sources": [{"id": "a", "kind": "x", "p": "${NOPE}"}]}, env={})

    def test_validation(self):
        for bad in [{}, {"sources": []}, {"sources": [{"kind": "x"}]}, {"sources": [{"id": "a b", "kind": "x"}]},
                    {"sources": [{"id": "a"}]}, {"sources": [{"id": "a", "kind": "x"}, {"id": "a", "kind": "x"}]}]:
            with self.assertRaises(C.ConfigError):
                C.parse(bad, env={})


class BadSettingsTests(unittest.TestCase):
    def test_bad_settings_become_clear_messages_not_tracebacks(self):
        from lookout_core.sources import SourceError, create_source
        bad = [{"id": "e", "kind": "elasticsearch", "url": "https://x", "ca_file": "/no/such/ca.pem"},
               {"id": "e", "kind": "elasticsearch", "url": "https://x", "timeout": "soon"},
               {"id": "o", "kind": "opencti", "url": "https://x", "timeout": "soon"},
               {"id": "s", "kind": "sqlite", "path": "x.db", "max_rows": "many", "entities": [{"table": "t", "id": "i", "name": "n"}]}]
        for cfg in bad:
            with self.assertRaisesRegex(SourceError, "invalid configuration|Source"):
                create_source(cfg)
        with self.assertRaisesRegex(SourceError, "ca.pem"):
            create_source(bad[0])


class ModelTests(unittest.TestCase):
    def test_record_normalisation(self):
        r = record(5, "Incident", "  ", description=None, aliases=["a", " ", None], meta=[("k", ""), ("S", 3)], date="2026-09-01 10:00:00")
        self.assertEqual((r["name"], r["aliases"], r["meta"], r["date"]), ("5", ["a"], [{"k": "S", "v": "3"}], "2026-09-01"))

    def test_browser_supplied_hashes_are_dropped(self):
        r = coerce_record({"id": "1", "name": "n", "type": "t", "evidence": {"path": "/p", "sha256": "f" * 64, "hashed_at": "x", "stable": True, "ai_derived": ["ocr"]}})
        self.assertEqual(r["evidence"], {"path": "/p", "ai_derived": ["ocr"]})

    def test_coerce_rejects_junk_and_roundtrips(self):
        with self.assertRaises(ValueError):
            coerce_record("nope")
        r = record(1, "T", "N", aliases=["x"], meta=[("a", "b")], code="c")
        self.assertEqual(coerce_record(r), r)


if __name__ == "__main__":
    unittest.main()
