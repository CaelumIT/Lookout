"""OpenCTI adapter (GraphQL). Works with OpenCTI 5.x and 6.x."""
import json
import re
import ssl
import urllib.error
import urllib.request

from ..models import record, relation
from .base import DataSource, SourceError

NAMED = ["AttackPattern", "Campaign", "Incident", "IntrusionSet", "Malware", "Tool",
         "Vulnerability", "Indicator", "Report", "Infrastructure", "Identity", "Location"]
# 6.x calls it ThreatActorGroup, 5.x called it ThreatActor. Try both, then a leaner field set.
VARIANTS = [("ThreatActorGroup", False), ("ThreatActor", False), ("ThreatActor", True), ("ThreatActorGroup", True)]
SCHEMA_ERR = re.compile(r"unknown type|cannot query field|graphql_validation|validation", re.I)
MARKINGS = "objectMarking { id definition_type definition }"


def node_fields(ta, lean):
    return f"""id entity_type created_at {"" if lean else "objectLabel { value }"}
    ... on AttackPattern {{ name description x_mitre_id }}
    ... on Campaign {{ name description {"" if lean else "first_seen last_seen"} }}
    ... on Incident {{ name description }}
    ... on IntrusionSet {{ name description aliases }}
    ... on Malware {{ name description {"" if lean else "malware_types aliases"} }}
    ... on {ta} {{ name description aliases }}
    ... on Tool {{ name description }}
    ... on Vulnerability {{ name description {"" if lean else "x_opencti_cvss_base_score"} }}
    ... on Indicator {{ name description pattern {"" if lean else "valid_from"} }}
    ... on Report {{ name description {"" if lean else "published"} }}
    ... on Infrastructure {{ name description }}
    ... on Identity {{ name description }}
    ... on Location {{ name description }}
    ... on StixCyberObservable {{ observable_value }}"""


def rel_fields(ta):
    frags = "\n    ".join(f"... on {t} {{ name }}" for t in [t for t in NAMED if t != "AttackPattern"] + [ta])
    return f"""... on BasicObject {{ entity_type }}
    ... on AttackPattern {{ name x_mitre_id }}
    {frags}
    ... on StixCyberObservable {{ observable_value }}"""


def to_record(n):
    t = n.get("entity_type") or "Unknown"
    obs = bool(n.get("observable_value"))
    fs, ls = n.get("first_seen") or "", n.get("last_seen") or ""
    meta = [("MITRE ID", n.get("x_mitre_id")), ("CVSS", n.get("x_opencti_cvss_base_score")),
            ("Published", (n.get("published") or "")[:10]),
            ("First seen", "" if fs.startswith("1970") else fs[:10]),
            ("Last seen", "" if ls.startswith("5138") else ls[:10]),
            ("Valid from", (n.get("valid_from") or "")[:10]),
            ("Malware types", ", ".join(n.get("malware_types") or []))]
    labels = [l.get("value") for l in n["objectLabel"] if isinstance(l, dict)] if isinstance(n.get("objectLabel"), list) else []
    rank = 3 if obs else 2 if re.search(r"report|indicator|incident", t, re.I) else 0
    return record(n["id"], t, n.get("name") or n.get("observable_value") or t, description=n.get("description"),
                  aliases=n.get("aliases") or [], labels=labels, meta=meta, code=n.get("pattern"),
                  date=n.get("created_at"), date_label="Added", rank=rank, observable=obs)


class OpenCTISource(DataSource):
    kind = "opencti"
    relationships = True
    default_examples = ["APT29", "Cobalt Strike", "T1059", "CVE-2024-3400", "LockBit"]
    default_questions = ["How are BlackCat and Fancy Bear linked?", "What tools does APT29 use?", "Which groups exploit CVE-2024-3400?"]

    def __init__(self, cfg, transport=None):
        """`transport(query) -> {"data": ...}` may be supplied (the OpenCTI connector passes pycti's client)."""
        super().__init__(cfg)
        self.url = str(cfg.get("url") or "").rstrip("/")
        self.token = str(cfg.get("token") or "")
        self.verify = cfg.get("verify_tls", True)
        self.timeout = int(cfg.get("timeout", 60))
        if not transport and not self.url:
            raise SourceError(f"Source '{self.id}': 'url' is required")
        self._transport = transport or self._http
        self.ta, self.lean, self._pinned = "ThreatActorGroup", False, False

    def describe(self):
        return "OpenCTI threat-intelligence platform (entities such as intrusion sets, malware, techniques, vulnerabilities, indicators and reports, with relationships)"

    # ---- transport ----
    def _http(self, query):
        req = urllib.request.Request(self.url + "/graphql", data=json.dumps({"query": query}).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.token})
        ctx = None if self.verify else ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                j = json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise SourceError(f"OpenCTI rejected the API token (HTTP {e.code})")
            try:
                j = json.loads(e.read())
            except ValueError:
                raise SourceError(f"OpenCTI answered HTTP {e.code}")
        except urllib.error.URLError as e:
            raise SourceError(f"Could not reach OpenCTI at {self.url}: {e.reason}")
        except OSError as e:
            raise SourceError(f"OpenCTI did not answer in time: {e}")
        if j.get("errors") and not j.get("data"):
            raise SourceError("; ".join(str(x.get("message", "error")) for x in j["errors"]))
        return j

    def _run(self, builder):
        variants = [(self.ta, self.lean)] if self._pinned else VARIANTS
        last = None
        for ta, lean in variants:
            try:
                res = self._transport(builder(ta, lean))
            except Exception as e:
                last = e
                if SCHEMA_ERR.search(str(e)):
                    continue
                raise
            if not res or res.get("data") is None:
                raise SourceError("OpenCTI returned no data. The account in use may lack access.")
            self.ta, self.lean, self._pinned = ta, lean, True
            return res["data"]
        raise SourceError(f"OpenCTI rejected the query: {last}")

    # ---- DataSource ----
    def test(self):
        d = self._run(lambda ta, lean: "query { me { name } }")
        if not d.get("me"):
            raise SourceError("The token was accepted but OpenCTI returned no user.")
        return f"Connected as {d['me']['name']}"

    def search(self, term, limit=30, filters=None):
        d = self._run(lambda ta, lean: f"""query {{ stixCoreObjects(search: {json.dumps(term)}, first: {int(limit)}) {{
            pageInfo {{ globalCount }} edges {{ node {{ {node_fields(ta, lean)} }} }} }} }}""")
        c = d["stixCoreObjects"]
        recs = [to_record(e["node"]) for e in c["edges"] if e.get("node")]
        return recs, (c.get("pageInfo") or {}).get("globalCount", len(recs))

    def get(self, record_id):
        d = self._run(lambda ta, lean: f"""query {{ stixCoreObject(id: {json.dumps(record_id)}) {{ {node_fields(ta, lean)} }} }}""")
        return to_record(d["stixCoreObject"]) if d.get("stixCoreObject") else None

    def markings(self, record_id):
        """(entity_type, markings) for TLP checks in the connector."""
        d = self._run(lambda ta, lean: f"""query {{ stixCoreObject(id: {json.dumps(record_id)}) {{ id entity_type {MARKINGS} }} }}""")
        o = d.get("stixCoreObject")
        if not o:
            raise SourceError(f"Entity {record_id} was not found or is not readable.")
        return o["entity_type"], o.get("objectMarking") or []

    def related(self, record_id, limit=80):
        lit = json.dumps(record_id)
        d = self._run(lambda ta, lean: f"""query {{
            out: stixCoreRelationships(fromId: {lit}, first: {int(limit)}) {{ edges {{ node {{ relationship_type to {{ {rel_fields(ta)} }} }} }} }}
            inc: stixCoreRelationships(toId: {lit}, first: {int(limit)}) {{ edges {{ node {{ relationship_type from {{ {rel_fields(ta)} }} }} }} }}
        }}""")
        seen, items = set(), []

        def add(rel, n, direction):
            name = (n or {}).get("name") or (n or {}).get("observable_value")
            if not name:
                return
            key = (n.get("entity_type"), name, rel, direction)
            if key not in seen:
                seen.add(key)
                items.append(relation(n.get("entity_type"), name, rel, direction, n.get("x_mitre_id")))

        for e in (d.get("out") or {}).get("edges", []):
            add(e["node"]["relationship_type"], e["node"].get("to"), "outbound")
        for e in (d.get("inc") or {}).get("edges", []):
            add(e["node"]["relationship_type"], e["node"].get("from"), "inbound")
        return items
