"""Search several data sources at once, and pivot indicators from one source into the others."""
import math
from concurrent.futures import ThreadPoolExecutor

from . import ioc as IOC
from .sources.base import SourceError

KIND_PRIORITY = ["sha256", "sha1", "md5", "ipv4", "ipv6", "domain", "url", "email", "cve", "technique"]


def _tag(records, src):
    for r in records:
        r["source"], r["source_label"] = src.id, src.label
    return records


class Federation:
    id = "*"
    label = "All sources"
    kind = "federation"
    is_federation = True

    def __init__(self, sources):
        self.sources = dict(sources)

    @property
    def relationships(self):
        return any(s.relationships for s in self.sources.values())

    @property
    def filter_keys(self):
        return tuple(sorted({k for s in self.sources.values() for k in s.filter_keys}))

    def info(self):
        desc = "; ".join(f"{s.label}: {s.describe()}" for s in self.sources.values())
        return {"id": self.id, "label": self.label, "kind": self.kind, "description": "Several data sources searched together. " + desc,
                "relationships": self.relationships, "examples": [], "questions": [],
                "filters": list(self.filter_keys), "evidence": any(s.content for s in self.sources.values())}

    def test(self):
        ok, bad = [], []
        for src in self.sources.values():
            try:
                src.test()
                ok.append(src.label)
            except Exception as e:
                bad.append(f"{src.label}: {e}")
        if not ok:
            raise SourceError("; ".join(bad))
        return f"{len(ok)} of {len(self.sources)} sources reachable" + (f". Problems: {'; '.join(bad)}" if bad else "")

    # ---- searching ----
    def search_all(self, term, limit=30, filters=None, only=None):
        """{"records": interleaved results, "total", "errors": {id: message}, "counts": {id: n}}"""
        targets = [s for sid, s in self.sources.items() if only is None or sid in only]
        per = max(3, math.ceil(limit / max(1, len(targets))) + 2)

        def one(src):
            try:
                f = {k: v for k, v in (filters or {}).items() if k in src.filter_keys}
                recs, total = src.search(term, per, filters=f) if f else src.search(term, per)
                return src.id, _tag(recs, src), total, None
            except Exception as e:                      # one failing source must not hide the others
                return src.id, [], 0, str(e) if isinstance(e, SourceError) else f"{type(e).__name__}: {e}"

        with ThreadPoolExecutor(max_workers=min(4, max(1, len(targets)))) as pool:
            results = list(pool.map(one, targets))
        errors = {sid: msg for sid, _, _, msg in results if msg}
        counts = {sid: len(recs) for sid, recs, _, _ in results}
        merged, i = [], 0                                # round-robin, so every source is represented
        lists = [recs for _, recs, _, _ in results]
        while len(merged) < limit and any(i < len(l) for l in lists):
            merged += [l[i] for l in lists if i < len(l)]
            i += 1
        total = sum(t or 0 for _, _, t, _ in results)
        return {"records": merged[:limit], "total": total, "errors": errors, "counts": counts}

    def search(self, term, limit=30, filters=None):
        r = self.search_all(term, limit, filters)
        if r["errors"] and len(r["errors"]) == len(self.sources):
            raise SourceError("; ".join(f"{k}: {v}" for k, v in r["errors"].items()))
        return r["records"], r["total"]

    def related_of(self, record):
        src = self.sources.get(record.get("source"))
        return src.related(record["id"]) if src else []

    # ---- evidence: indicators found in one source, looked up in the others ----
    def pivot(self, groups, per_group=4, total=12):
        pivots, done = [], 0
        for g in groups:
            cands = {}

            def note(text, origin):
                for ind in IOC.extract(text):
                    c = cands.setdefault((ind["kind"], ind["value"]), {"ioc": ind, "origins": set()})
                    c["origins"].add(origin)

            for r in g["records"]:
                note(" ".join([r["name"], r["description"], r.get("code") or "", *r["aliases"], *[m["v"] for m in r["meta"]]]), r.get("source"))
            for it in g["related"]:
                note(it["name"], it.get("source"))
            ordered = sorted(cands.values(), key=lambda c: KIND_PRIORITY.index(c["ioc"]["kind"]) if c["ioc"]["kind"] in KIND_PRIORITY else 99)
            own = {(r.get("source"), r["id"]) for r in g["records"]}
            for c in ordered[:per_group]:
                if done >= total:
                    return pivots
                done += 1
                others = [sid for sid in self.sources if sid not in c["origins"]]
                if not others:
                    continue
                found = self.search_all(IOC.search_term(c["ioc"]), 5, only=others)["records"]
                hits = [r for r in found if (r.get("source"), r["id"]) not in own]
                if hits:
                    pivots.append({"ioc": c["ioc"], "group": g["asked"], "origin_sources": sorted(x for x in c["origins"] if x), "hits": hits[:6]})
        return pivots
