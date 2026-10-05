"""Central configuration: every secret comes from the environment (optionally via a .env file).

No secret is ever read from, or written to, the data directory. See .env.example for the full list and
`python -m tracevault.keygen` to generate a fresh set of values.
"""
import os

from dotenv import dotenv_values, find_dotenv

class ConfigError(RuntimeError):
    """A required setting is missing or malformed."""

_loaded = False

def load_env(path: str | None = None, force: bool = False) -> None:
    """Load a .env file into os.environ (real environment variables always win)."""
    global _loaded
    if _loaded and not force:
        return
    path = path or os.environ.get("TV_ENV_FILE") or find_dotenv(usecwd=True)
    if path and os.path.exists(path):
        for k, v in dotenv_values(path).items():
            if v is not None:
                os.environ.setdefault(k, v)
    _loaded = True

def env(name: str, default: str | None = None) -> str:
    load_env()
    v = os.environ.get(name, default)
    if v is None or v == "":
        raise ConfigError(f"Missing required setting {name}. Copy .env.example to .env and fill it in "
                          f"(run `python -m tracevault.keygen` to generate values).")
    return v

def env_int(name: str, default: int) -> int:
    load_env()
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        raise ConfigError(f"{name} must be an integer")

def env_bool(name: str, default: bool = False) -> bool:
    load_env()
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes", "on")
