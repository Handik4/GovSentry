"""Minimal .env loader shared by the deployment scripts (no extra dependency)."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_env() -> dict:
    """Return os.environ overlaid on top of KEY=VALUE pairs from ROOT/.env."""
    values: dict = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    values.update(os.environ)
    return values
