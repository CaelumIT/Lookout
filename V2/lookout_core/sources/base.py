"""The contract every data source implements."""


class SourceError(RuntimeError):
    """A problem talking to a data source. The message is safe to show to the user."""


class DataSource:
    kind = "base"
    relationships = False          # True when related() can return something
    default_examples = []          # starter searches shown on the empty screen
    default_questions = []         # starter plain-English questions
    filter_keys = ()               # filters this source can apply: category, date_from, date_to, path_contains

    def __init__(self, cfg):
        self.id = cfg["id"]
        self.label = cfg.get("label") or self.id
        self.user_description = str(cfg.get("description") or "").strip()
        self.examples = list(cfg.get("examples") or self.default_examples)
        self.questions = list(cfg.get("questions") or self.default_questions)
        from ..evidence import ContentAccess, EvidenceError
        try:
            self.content = ContentAccess.from_cfg(cfg.get("content"))       # optional: lets Lookout read and hash files
        except EvidenceError as e:
            raise SourceError(f"Source '{self.id}': {e}")

    # ---- implement these ----
    def describe(self):
        """One line telling the model (and the user) what this data is."""
        return self.kind

    def test(self):
        """Check the connection and the configuration. Return a short message or raise SourceError."""
        raise NotImplementedError

    def search(self, term, limit=30, filters=None):
        """Return (records, total). `total` may be None when the source cannot count cheaply.
        `filters` is only passed when the source lists keys in `filter_keys`."""
        raise NotImplementedError

    def get(self, record_id):
        """Return one record by id, or None."""
        raise NotImplementedError

    def related(self, record_id, limit=80):
        """Return relations for a record. Sources without relationship data return []."""
        return []

    # ---- provided ----
    def info(self):
        desc = " ".join(x for x in [self.describe(), self.user_description] if x)
        return {"id": self.id, "label": self.label, "kind": self.kind, "description": desc,
                "relationships": bool(self.relationships), "examples": self.examples, "questions": self.questions,
                "filters": list(self.filter_keys), "evidence": self.content is not None}
