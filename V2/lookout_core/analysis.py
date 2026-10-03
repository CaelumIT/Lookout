"""Source-independent logic: matching, link analysis, payload building and prompt assembly.
Everything here works on normalised records and relations, never on a specific database."""
import json
import re

from .models import coerce_record, coerce_relation

TLP_ORDER = {"TLP:CLEAR": 0, "TLP:WHITE": 0, "TLP:GREEN": 1, "TLP:AMBER": 2, "TLP:AMBER+STRICT": 3, "TLP:RED": 4}
FILTER_KEYS = ("category", "date_from", "date_to", "path_contains")


def clip(s, n):
    s = str(s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def names_of(r):
    return [x.lower() for x in [r["name"], *r.get("aliases", [])] if x]


def type_label(t):
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", (t or "").replace("-", " ")).lower()
    return s[:1].upper() + s[1:]


def dumps(o):
    return json.dumps(o, ensure_ascii=False)


# ---------- what the model sees ----------
def condense(r, dlen=280, with_source=False):
    """Trim a record to what the model needs. Empty fields are dropped to save tokens."""
    o = {"type": r["type"], "name": r["name"], "aliases": r["aliases"][:6], "description": clip(r["description"], dlen),
         "labels": r["labels"][:6], "code": clip(r["code"], 120) if r.get("code") else None, "date": r.get("date")}
    if with_source:
        o["source"] = r.get("source_label")
    ev = r.get("evidence")
    if ev:
        o["evidence"] = {k: ev[k] for k in ("path", "modified", "indexed", "sha256", "ai_derived") if ev.get(k)}
    for m in r.get("meta", []):
        o.setdefault(m["k"].lower().replace(" ", "_"), m["v"])
    return {k: v for k, v in o.items() if v not in (None, "", [], {})}


def rel_summary(items, per=12):
    g = {}
    for r in items:
        code = f" {r['code']}" if r.get("code") else ""
        d = "inbound " if r["dir"] == "inbound" else ""
        g.setdefault(r["type"], {})[f"{r['name']}{code} ({d}{r['rel']})"] = None
    return {k: list(v)[:per] for k, v in g.items()}


def tidy(text):
    return re.sub(r"(?im)^(#+\s*)suggested searches\s*:?\s*$", r"\1Suggested searches", text.strip())


def tlp_allowed(markings, max_tlp):
    limit = TLP_ORDER.get(str(max_tlp).upper())
    if limit is None:
        raise ValueError(f"Unknown TLP limit: {max_tlp}")
    for m in markings or []:
        if m.get("definition_type") == "TLP":
            rank = TLP_ORDER.get(str(m.get("definition")).upper())
            if rank is None or rank > limit:     # an unknown TLP value counts as too high
                return False
    return True


# ---------- plain-English questions ----------
def clean_filters(f):
    out = {}
    if isinstance(f, dict):
        for k in FILTER_KEYS:
            v = str(f.get(k) or "").strip()
            if not v or (k.startswith("date_") and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", v)):
                continue
            out[k] = v[:200]
    return out


def parse_plan(raw, question):
    try:
        j = json.loads(raw)
    except (ValueError, TypeError):
        j = {}
    j = j if isinstance(j, dict) else {}
    ents = []
    for e in j.get("entities") if isinstance(j.get("entities"), list) else []:
        if isinstance(e, str):
            name, aliases = e.strip(), []
        elif isinstance(e, dict):
            name = str(e.get("name") or "").strip()
            aliases = [str(a).strip() for a in (e.get("aliases") if isinstance(e.get("aliases"), list) else []) if str(a).strip()][:3]
        else:
            continue
        if name:
            ents.append({"name": name, "aliases": aliases})
    return {"entities": ents[:4] or [{"name": question, "aliases": []}], "intent": str(j.get("intent") or "other"),
            "filters": clean_filters(j.get("filters"))}


def pick_records(records, term):
    t = term.lower()
    exact = [r for r in records if t in names_of(r)]
    if exact:
        return exact[:2]
    ranked = sorted(enumerate(records), key=lambda p: (p[1].get("rank", 0), p[0]))
    return [ranked[0][1]] if ranked else []


def _related(source, r):
    return source.related_of(r) if hasattr(source, "related_of") else source.related(r["id"])


def iter_context(question, source, llm, plan_prompt):
    """Generator: yields {"progress": text} while working, then {"context": {...}}.

    The model only extracts names (and optional filters). Searching, matching, link analysis and
    indicator pivots are done in code, because set intersection is exact and models are unreliable at it.
    `source` may be a single data source or a Federation."""
    yield {"progress": "Reading your question…"}
    raw = llm.chat([{"role": "system", "content": plan_prompt}, {"role": "user", "content": question}],
                   json_mode=True, num_ctx=2048, temperature=0.1)
    plan = parse_plan(raw, question)
    fk = set(getattr(source, "filter_keys", ()) or ())
    filters = {k: v for k, v in plan["filters"].items() if k in fk}
    fed = bool(getattr(source, "is_federation", False))
    groups, missing, used = [], [], set()
    for ent in plan["entities"]:
        yield {"progress": f"Searching for {ent['name']}…"}
        picked, exact = [], False
        for t in [ent["name"], *ent["aliases"]]:
            recs, _ = source.search(t, 8, filters=filters) if filters else source.search(t, 8)
            p = pick_records(recs, t)
            if not p:
                continue
            is_exact = t.lower() in names_of(p[0])
            if not picked or (is_exact and not exact):
                picked, exact = p, is_exact
            if exact:
                break
        found = bool(picked)
        picked = [r for r in picked if (r.get("source"), r["id"]) not in used]
        if not picked:
            if not found:     # found-but-already-matched means two names for one record: merge silently
                missing.append(ent["name"])
            continue
        used.update((r.get("source"), r["id"]) for r in picked)
        groups.append({"asked": ent["name"], "records": picked, "exact": exact, "related": []})

    for g in groups:
        yield {"progress": f"Checking what {g['asked']} is connected to…"}
        seen = set()
        for r in g["records"]:
            for it in _related(source, r):
                k = (it["type"], it["name"], it["rel"], it["dir"])
                if k not in seen:
                    seen.add(k)
                    g["related"].append({**it, "source": r.get("source")})

    pivots = []
    if fed and groups:
        yield {"progress": "Looking for indicators that appear in other sources…"}
        pivots = source.pivot(groups)

    direct, shared = [], []
    if len(groups) > 1:
        dseen = set()
        for a in groups:
            for b in groups:
                if a is b:
                    continue
                bn = {x for r in b["records"] for x in names_of(r)}
                for it in a["related"]:
                    if it["name"].lower() in bn:
                        frm, to = (b["asked"], a["asked"]) if it["dir"] == "inbound" else (a["asked"], b["asked"])
                        k = (frm, it["rel"], to)
                        if k not in dseen:
                            dseen.add(k)
                            direct.append({"from": frm, "relationship": it["rel"], "to": to})
        m = {}
        for g in groups:
            for it in g["related"]:
                e = m.setdefault((it["type"].lower(), it["name"].lower()), {"type": it["type"], "name": it["name"], "via": {}})
                e["via"].setdefault(g["asked"], set()).add(it["rel"])
        shared = [{"type": e["type"], "name": e["name"], "via": {k: sorted(v) for k, v in e["via"].items()}}
                  for e in m.values() if len(e["via"]) >= 2]
    yield {"context": {"question": question, "intent": plan["intent"], "groups": groups, "missing": missing, "filters": filters,
                       "direct": direct, "shared": shared[:40], "pivots": pivots, "federated": fed,
                       "relationships": bool(source.relationships)}}


def build_context(question, source, llm, plan_prompt):
    for ev in iter_context(question, source, llm, plan_prompt):
        if "context" in ev:
            return ev["context"]


def coerce_context(c):
    """Rebuild a context received from a client."""
    if not isinstance(c, dict) or not isinstance(c.get("groups"), list):
        raise ValueError("Invalid context")
    groups = [{"asked": str(g.get("asked", "")), "exact": bool(g.get("exact")),
               "records": [coerce_record(r) for r in g.get("records", [])],
               "related": [coerce_relation(r) for r in g.get("related", [])]} for g in c["groups"]]
    pivots = [{"ioc": {"kind": str(p["ioc"].get("kind", "")), "value": str(p["ioc"].get("value", ""))},
               "group": str(p.get("group", "")), "origin_sources": [str(x) for x in p.get("origin_sources", [])],
               "hits": [coerce_record(h) for h in p.get("hits", [])]}
              for p in c.get("pivots", []) if isinstance(p, dict) and isinstance(p.get("ioc"), dict)]
    return {"question": str(c.get("question", "")), "intent": str(c.get("intent", "other")), "groups": groups,
            "missing": [str(x) for x in c.get("missing", [])], "relationships": bool(c.get("relationships")),
            "federated": bool(c.get("federated")), "filters": clean_filters(c.get("filters")), "pivots": pivots,
            "direct": [d for d in c.get("direct", []) if isinstance(d, dict)],
            "shared": [s for s in c.get("shared", []) if isinstance(s, dict)]}


def context_records(ctx):
    """Every record in a context, including pivot hits."""
    return [r for g in ctx["groups"] for r in g["records"]] + [h for p in ctx.get("pivots", []) for h in p["hits"]]


def context_payload(ctx, dlen=280, per=12):
    ws = ctx.get("federated", False)
    payload = {"question": ctx["question"], "intent": ctx["intent"], "relationships_available": ctx["relationships"],
               "entities": [{"asked_as": g["asked"], "closest_match": not g["exact"],
                             "records": [condense(r, dlen, ws) for r in g["records"]],
                             "related_by_type": rel_summary(g["related"], per)} for g in ctx["groups"]],
               "direct_links": ctx["direct"], "shared_connections": ctx["shared"][:30], "not_found": ctx["missing"]}
    if ctx.get("filters"):
        payload["filters_applied"] = ctx["filters"]
    if ctx.get("pivots"):
        payload["pivots"] = [{"indicator": p["ioc"], "found_in_group": p["group"], "found_in_sources": p["origin_sources"],
                              "also_matches": [condense(h, 160, True) for h in p["hits"]]} for p in ctx["pivots"]]
    return payload


def understood_markdown(ctx):
    """Deterministic provenance section, so readers can see how a question was interpreted."""
    ws = ctx.get("federated", False)
    out = ["### How the question was understood"]
    for g in ctx["groups"]:
        matched = " and ".join(f"{r['name']} ({type_label(r['type']).lower()}{', ' + r['source_label'] if ws and r.get('source_label') else ''})"
                               for r in g["records"])
        out.append(f"- **{g['asked']}** matched {matched}" + ("" if g["exact"] else " (closest match only)"))
    out += [f"- No record found for **{m}**" for m in ctx["missing"]]
    if ctx.get("filters"):
        out.append("- Filters applied: " + ", ".join(f"{k.replace('_', ' ')} = {v}" for k, v in ctx["filters"].items()))
    if len(ctx["groups"]) > 1:
        if not ctx["relationships"]:
            out.append("\n*" + ("None of these data sources has relationship data" if ws else "This data source has no relationship data") + ", so links between the entities cannot be assessed.*")
        else:
            out.append("\n### Direct links")
            out += [f"- **{d['from']}** {d['relationship'].replace('-', ' ')} **{d['to']}**" for d in ctx["direct"]] \
                or ["- No direct relationship is recorded between them."]
            out.append(f"\n### Shared connections ({len(ctx['shared'])})")
            out += [f"- {s['name']} ({type_label(s['type']).lower()})" for s in ctx["shared"][:30]] or ["- Nothing in common was found."]
    if ctx.get("pivots"):
        out.append("\n### Indicators that appear in other sources")
        for p in ctx["pivots"]:
            hits = ", ".join(f"{h['name']} ({h.get('source_label') or 'source'})" for h in p["hits"])
            out.append(f"- `{p['ioc']['value']}` ({p['ioc']['kind']}) from {p['group']}: also matches {hits}")
        out.append("\n*These are text matches on the indicator. They are leads, not proof of a relationship.*")
    return "\n".join(out)


def evidence_appendix(records, hashes=None):
    """Deterministic list of the files behind a bulletin. Hashes appear only where this session computed them."""
    hashes, rows, seen = hashes or {}, [], set()
    for r in records:
        ev = r.get("evidence")
        key = (r.get("source"), r["id"])
        if not ev or not ev.get("path") or key in seen:
            continue
        seen.add(key)
        h = hashes.get(key) or {}
        bits = [f"path `{ev['path']}`"]
        if ev.get("modified"):
            bits.append(f"modified {ev['modified']} (per the index)")
        if ev.get("indexed"):
            bits.append(f"indexed {ev['indexed']}")
        bits.append(f"SHA-256 `{h['sha256']}` (computed {h.get('hashed_at', 'this session')}{'' if h.get('stable', True) else ', the file changed while being read'})"
                    if h.get("sha256") else "SHA-256 not verified")
        if ev.get("ai_derived"):
            bits.append("machine-generated text: " + ", ".join(ev["ai_derived"]))
        rows.append(f"- **{r['name']}**" + (f" ({r['source_label']})" if r.get("source_label") else "") + ": " + "; ".join(bits))
    if not rows:
        return ""
    return ("\n\n## Evidence appendix\nFiles referred to above, as described by the file index. Treat machine-generated text "
            "(OCR, image descriptions, summaries, transcripts) as a lead to check against the original.\n" + "\n".join(rows))


# ---------- prompt assembly ----------
def entity_payload(record, related, date, dlen=1500, per=30):
    return {"date": date, "entity": {"record": condense(record, dlen), "related_by_type": rel_summary(related, per)}}


def prepare(kind, req, info, prompts, source, date):
    """Generator: yields {"progress": ...} while gathering data, then {"messages": [...], "num_ctx": n}.

    req keys: term, total, records, context (optional), focus (optional {record, related})."""
    label = info["label"]
    ws = info.get("kind") == "federation"
    ctx = req.get("context")
    records = req.get("records") or []
    focus = req.get("focus")
    if kind == "recommend":
        if ctx:
            system = prompts["question"]
            user = f'The analyst asked: "{req["term"]}"\n\nWhat {label} returned (JSON):\n{dumps(context_payload(ctx))}'
        else:
            payload = {"search_term": req["term"], "total_matches": req.get("total"), "results": [condense(r, 280, ws) for r in records[:15]]}
            system = prompts["recommend"]
            user = f'The analyst searched {label} for "{req["term"]}".\n\nResults (JSON):\n{dumps(payload)}'
        if focus:
            g = {}
            for r in focus["related"]:
                g.setdefault(r["type"], []).append(r["name"])
            g = {k: list(dict.fromkeys(v))[:12] for k, v in g.items()}
            user += (f"\n\nThe analyst has opened this record and wants advice on it specifically:\n{dumps(condense(focus['record'], 280, ws))}"
                     f"\nIts related entities by type (JSON):\n{dumps(g)}\nFocus the summary and suggestions on this record.")
        yield {"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}], "num_ctx": 8192}
        return
    if kind == "bulletin":
        if ctx:
            yield {"progress": "Using the relationships already gathered…"}
            yield {"used": context_records(ctx)}
            payload = {"date": date, **context_payload(ctx, 700, 25)}
        else:
            recs = [r for r in records if not r.get("observable")] or list(records)
            if focus:
                recs = [focus["record"]] + [r for r in recs if r["id"] != focus["record"]["id"]]
            top, entities = recs[:5], []
            yield {"used": top}
            for r in top:
                yield {"progress": f"Gathering relationships for {r['name']}…"}
                try:
                    rel = _related(source, r)
                except Exception:
                    rel = []
                entities.append({"record": condense(r, 700, ws), "related_by_type": rel_summary(rel, 25)})
            ids = {(r.get("source"), r["id"]) for r in top}
            payload = {"date": date, "search_term": req["term"], "total_matches": req.get("total"), "entities": entities,
                       "relationships_available": bool(source.relationships),
                       "other_matches": [{"type": r["type"], "name": r["name"]} for r in records if (r.get("source"), r["id"]) not in ids][:10]}
        yield {"messages": [{"role": "system", "content": prompts["bulletin"]},
                            {"role": "user", "content": f"Write the bulletin from this data (JSON):\n{dumps(payload)}"}],
               "num_ctx": 12288}
        return
    raise ValueError(f"Unknown generation kind: {kind}")
