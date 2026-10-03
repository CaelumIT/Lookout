import os
import sys
import tempfile
import tomllib
import unittest

import helpers  # noqa: F401
from lookout_core import config as C
from lookout_core.federated import Federation
from lookout_core.sources import create_sources

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "examples"))
import make_demo  # noqa: E402


class DemoTests(unittest.TestCase):
    def test_demo_config_runs_end_to_end(self):
        db = os.path.join(tempfile.mkdtemp(), "demo.db")
        make_demo.build(db)
        with open(os.path.join(ROOT, "examples", "lookout.demo.toml"), "rb") as f:
            raw = tomllib.load(f)
        raw["sources"][0]["path"] = db                                     # the shipped file uses paths relative to the repo root
        raw["sources"][1]["fixture"] = os.path.join(ROOT, "examples", "qsirch_synthetic.json")
        raw["sources"][1]["content"]["path_map"][0]["local"] = os.path.join(ROOT, "examples", "evidence")
        fed = Federation(create_sources(C.parse(raw)["sources"]))
        self.assertIn("2 of 2", fed.test())
        recs, _ = fed.sources["intel"].search("APT-Example")
        for r in recs:
            r["source"], r["source_label"] = "intel", "Demo intel"
        group = {"asked": "APT-Example", "records": recs, "exact": True,
                 "related": [{**x, "source": "intel"} for x in fed.sources["intel"].related(recs[0]["id"])]}
        found = {p["ioc"]["value"]: {h["name"] for h in p["hits"]} for p in fed.pivot([group])}
        self.assertEqual(found["203.0.113.50"], {"incident-notes.txt", "whiteboard.jpg"})
        self.assertIn("incident-notes.txt", found["evil-update.example.com"])
        self.assertIn("mail-2026-09-30.eml", found["evil-update.example.com"])


if __name__ == "__main__":
    unittest.main()
