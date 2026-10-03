"""Source registry. Adapters are imported lazily, so a missing database driver only affects the source that needs it."""
import importlib

from .base import DataSource, SourceError  # noqa: F401

KINDS = {
    "opencti": ("opencti", "OpenCTISource"),
    "elasticsearch": ("elastic", "ElasticSource"),
    "opensearch": ("elastic", "ElasticSource"),
    "mysql": ("sql", "SQLSource"),
    "mariadb": ("sql", "SQLSource"),
    "postgres": ("sql", "SQLSource"),
    "sqlite": ("sql", "SQLSource"),
    "qsirch": ("qsirch", "QsirchSource"),
}


def create_source(cfg, **kwargs):
    kind = str(cfg.get("kind", "")).lower()
    if kind not in KINDS:
        raise SourceError(f"Source '{cfg.get('id')}': unknown kind '{kind}'. Supported: {', '.join(sorted(KINDS))}")
    module, cls = KINDS[kind]
    try:
        return getattr(importlib.import_module(f"lookout_core.sources.{module}"), cls)({**cfg, "kind": kind}, **kwargs)
    except SourceError:
        raise
    except (KeyError, ValueError, TypeError, OSError) as e:      # a bad setting must give a message, not a traceback
        detail = f"cannot read {e.filename!r}" if isinstance(e, FileNotFoundError) and e.filename else f"{type(e).__name__}: {e}"
        raise SourceError(f"Source '{cfg.get('id')}': invalid configuration ({detail})")


def create_sources(cfgs):
    return {c["id"]: create_source(c) for c in cfgs}
