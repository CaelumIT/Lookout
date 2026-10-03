"""Configuration: a TOML file with ${ENV_VAR} expansion so secrets stay out of the file."""
import os
import re
import tomllib


class ConfigError(ValueError):
    pass


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_ID = re.compile(r"^[A-Za-z0-9_-]+$")


def expand(value, env=None):
    env = os.environ if env is None else env
    if isinstance(value, str):
        def sub(m):
            if m.group(1) not in env:
                raise ConfigError(f"Environment variable {m.group(1)} is not set (referenced as ${{{m.group(1)}}} in the config)")
            return env[m.group(1)]
        return _VAR.sub(sub, value)
    if isinstance(value, list):
        return [expand(v, env) for v in value]
    if isinstance(value, dict):
        return {k: expand(v, env) for k, v in value.items()}
    return value


def parse(raw, env=None):
    cfg = expand(raw, env)
    cfg.setdefault("server", {})
    ollama = cfg.setdefault("ollama", {})
    ollama.setdefault("url", "http://localhost:11434")
    ollama.setdefault("timeout", 600)
    sources = cfg.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ConfigError("The config defines no [[sources]]. Add at least one (see lookout.example.toml).")
    seen = set()
    for s in sources:
        sid = s.get("id")
        if not sid or not _ID.match(str(sid)):
            raise ConfigError(f"Every source needs an 'id' made of letters, digits, '-' or '_' (got {sid!r})")
        if sid in seen:
            raise ConfigError(f"Duplicate source id: {sid}")
        seen.add(sid)
        if not s.get("kind"):
            raise ConfigError(f"Source '{sid}' has no 'kind'")
    return cfg


def load(path):
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError:
        raise ConfigError(f"Config file not found: {path}. Copy lookout.example.toml to lookout.toml and edit it.")
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path} is not valid TOML: {e}")
    return parse(raw)
