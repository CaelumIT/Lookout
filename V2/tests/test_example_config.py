import os
import tomllib
import unittest

import helpers  # noqa: F401
from lookout_core import config as C
from lookout_core.sources import create_sources

ROOT = os.path.join(os.path.dirname(__file__), "..")


class ExampleConfigTests(unittest.TestCase):
    def test_example_parses_and_every_source_builds(self):
        with open(os.path.join(ROOT, "lookout.example.toml"), "rb") as f:
            raw = tomllib.load(f)
        cfg = C.parse(raw, env={"OPENCTI_TOKEN": "t", "ES_API_KEY": "k", "INCIDENTS_DB_PASSWORD": "p"})
        sources = create_sources(cfg["sources"])
        self.assertEqual(list(sources), ["opencti", "logs", "incidents"])
        self.assertEqual([s.kind for s in sources.values()], ["opencti", "elasticsearch", "mariadb"])
        self.assertEqual([s.relationships for s in sources.values()], [True, True, True])
        self.assertEqual(sources["incidents"].info()["questions"], ["Which incidents affected the same assets?"])
        self.assertIn("incidents (Incident)", sources["incidents"].describe())
        self.assertEqual(sources["logs"].pivots["IP"], ["source.ip"])


if __name__ == "__main__":
    unittest.main()
