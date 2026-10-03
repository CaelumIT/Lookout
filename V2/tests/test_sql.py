import unittest

import helpers
from lookout_core.sources import SourceError, create_source
from lookout_core.sources.sql import SQLSource


class SqliteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = create_source(helpers.sql_cfg(helpers.make_sqlite()))

    def test_search_maps_columns(self):
        recs, total = self.src.search("ransomware")
        r = recs[0]
        self.assertEqual((r["id"], r["type"], r["name"]), ("incidents:1", "Incident", "Ransomware on FIN-01"))
        self.assertEqual(r["aliases"], ["BlackCat Hit"])
        self.assertEqual(r["labels"], ["ransomware", "finance"])
        self.assertEqual({m["k"]: m["v"] for m in r["meta"]}, {"Status": "open", "Severity": "high"})
        self.assertEqual((r["date"], total), ("2026-09-01", len(recs)))

    def test_searches_every_configured_table_and_column(self):
        names = {r["name"] for r in self.src.search("fin-01")[0]}
        self.assertEqual(names, {"Ransomware on FIN-01", "FIN-01"})     # incident title and asset hostname
        self.assertEqual([r["id"] for r in self.src.search("volumes")[0]], ["incidents:1"])   # a column that is only in 'notes'

    def test_like_wildcards_are_literal_and_injection_is_inert(self):
        self.assertEqual([r["id"] for r in self.src.search("50%")[0]], ["incidents:1"])
        self.assertEqual([r["id"] for r in self.src.search("_")[0]], ["incidents:3"])    # only the name containing an underscore
        self.assertEqual(self.src.search("'; DROP TABLE incidents; --")[0], [])
        self.assertEqual(len(self.src.search("ransomware")[0]), 1)                        # table still there

    def test_get_and_related(self):
        self.assertEqual(self.src.get("incidents:2")["name"], "Phishing campaign")
        self.assertIsNone(self.src.get("incidents:99"))
        self.assertIsNone(self.src.get("nonsense"))
        rel = self.src.related("incidents:2")
        self.assertEqual(sorted(r["name"] for r in rel), ["FIN-01", "HR-02"])
        self.assertTrue(all(r["rel"] == "affects" and r["type"] == "Asset" for r in rel))
        self.assertEqual(self.src.related("assets:1"), [])         # no relation configured for assets
        self.assertTrue(self.src.info()["relationships"])

    def test_connection_is_read_only(self):
        with self.assertRaisesRegex(SourceError, "rejected"):
            self.src._run("DELETE FROM incidents")

    def test_test_checks_tables_and_relations(self):
        self.assertIn("2 table(s)", self.src.test())
        bad = helpers.sql_cfg(helpers.make_sqlite())
        bad["entities"][0]["name"] = "no_such_column"
        with self.assertRaisesRegex(SourceError, "no_such_column"):
            create_source(bad).test()

    def test_config_validation(self):
        base = helpers.sql_cfg("x.db")
        for mutate, msg in [
            (lambda c: c["entities"][0].update(table="a;DROP"), "plain table"),
            (lambda c: c["entities"][0].update(search=["title) OR 1=1 --"]), "plain table"),
            (lambda c: c["relations"][0].update(sql="DELETE FROM incidents"), "single SELECT"),
            (lambda c: c["relations"][0].update(sql="SELECT 1; DROP TABLE x"), "single SELECT"),
            (lambda c: c.update(entities=[]), "at least one"),
        ]:
            import copy
            c = copy.deepcopy(base)
            mutate(c)
            with self.assertRaisesRegex(SourceError, msg):
                create_source(c)


class DialectTests(unittest.TestCase):
    """The SQL text for engines that cannot be run here."""

    def make(self, kind):
        c = helpers.sql_cfg("x.db")
        c.update(kind=kind, host="h", user="u", database="d")
        return SQLSource(c)

    def test_mysql(self):
        s = self.make("mysql")
        sql, params = s.build_search(s.entities[0], "a_b%", 10)
        self.assertIn("`incidents`", sql)
        self.assertIn("`title` LIKE %s ESCAPE '!'", sql)
        self.assertEqual(params[0], "%a!_b!%%")
        self.assertEqual(len(params), 4)            # three search columns plus the ORDER BY term
        self.assertEqual(sql.count("%s"), 4)

    def test_mariadb_fulltext(self):
        c = helpers.sql_cfg("x.db")
        c.update(kind="mariadb", host="h")
        c["entities"][0]["search_mode"] = "fulltext"
        s = SQLSource(c)
        sql, params = s.build_search(s.entities[0], "blackcat", 5)
        self.assertIn("MATCH(`title`, `summary`, `notes`) AGAINST (%s IN NATURAL LANGUAGE MODE)", sql)
        self.assertEqual(params, ["blackcat", "blackcat"])

    def test_postgres_uses_ilike_and_double_quotes(self):
        s = self.make("postgres")
        sql, _ = s.build_search(s.entities[0], "x", 5)
        self.assertIn('"title" ILIKE %s', sql)

    def test_fulltext_rejected_outside_mysql(self):
        c = helpers.sql_cfg("x.db")
        c["entities"][0]["search_mode"] = "fulltext"
        with self.assertRaisesRegex(SourceError, "only available"):
            SQLSource(c).build_search(SQLSource(c).entities[0], "x", 5)

    def test_relation_binding_escapes_percent_for_format_drivers(self):
        s = self.make("mysql")
        sql, params = s.bind_relation("SELECT 'x' AS name FROM t WHERE c LIKE 'a%' AND id = :id", "7")
        self.assertEqual((sql, params), ("SELECT 'x' AS name FROM t WHERE c LIKE 'a%%' AND id = %s", [7]))
        sql, params = self.make("sqlite").bind_relation("SELECT :id, :id", "abc")
        self.assertEqual((sql, params), ("SELECT ?, ?", ["abc", "abc"]))

    def test_missing_driver_gives_install_hint(self):
        import sys
        if "pymysql" in sys.modules:
            self.skipTest("pymysql is installed")
        with self.assertRaisesRegex(SourceError, "pip install pymysql"):
            self.make("mysql")._connect()


if __name__ == "__main__":
    unittest.main()
