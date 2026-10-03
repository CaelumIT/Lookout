#!/usr/bin/env python3
"""Create a small SYNTHETIC SQLite 'intel' database for trying Lookout without any servers.

    python3 examples/make_demo.py            # writes examples/demo_intel.db
    python3 web/server.py --config examples/lookout.demo.toml

The demo pairs it with sample file-index data (examples/qsirch_synthetic.json), so you can see
cross-source search and indicator pivots: the actor's infrastructure shows up in the sample files."""
import os
import sqlite3
import sys


def build(path):
    if os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.executescript("""
    CREATE TABLE actors(id INTEGER PRIMARY KEY, name TEXT, aliases TEXT, about TEXT);
    CREATE TABLE infra(actor_id INTEGER, value TEXT, kind TEXT);
    INSERT INTO actors VALUES
      (1, 'APT-Example', 'Example Bear; ExBear', 'Synthetic threat actor. Operates command-and-control at 203.0.113.50 and evil-update.example.com. Uses PowerShell (T1059.001).'),
      (2, 'Other Group', '', 'Synthetic group that is unrelated to the sample files.');
    INSERT INTO infra VALUES
      (1, '203.0.113.50', 'IPv4-Addr'), (1, 'evil-update.example.com', 'Domain-Name'),
      (1, 'PowerShell', 'Attack-Pattern'), (2, '198.51.100.7', 'IPv4-Addr');
    """)
    db.commit()
    db.close()


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_intel.db")
    build(out)
    print(f"Wrote {out}")
