"""Configuración del servicio, leída de variables de entorno."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_TRUE = {"1", "true", "yes", "on", "si", "sí"}
_REVOCATION_MODES = {"soft-fail", "hard-fail", "require"}
_DEFAULT_CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in _TRUE


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    certs_dir: Path
    use_system_certs: bool
    trust_refresh_seconds: int
    expiry_warning_days: int
    max_upload_bytes: int
    validation_timeout_seconds: int
    revocation_mode: str
    allow_fetching: bool
    log_level: str


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    revocation_mode = os.getenv("REVOCATION_MODE", "soft-fail").strip().lower()
    if revocation_mode not in _REVOCATION_MODES:
        raise ValueError(
            f"REVOCATION_MODE='{revocation_mode}' no es válido; "
            f"valores admitidos: {sorted(_REVOCATION_MODES)}"
        )
    return Settings(
        certs_dir=Path(os.getenv("CERTS_DIR", str(_DEFAULT_CERTS_DIR))),
        use_system_certs=_env_bool("USE_SYSTEM_CERTS", True),
        trust_refresh_seconds=_env_int("TRUST_REFRESH_SECONDS", 3600),
        expiry_warning_days=_env_int("CERT_EXPIRY_WARNING_DAYS", 30),
        max_upload_bytes=_env_int("MAX_UPLOAD_MB", 25) * 1024 * 1024,
        validation_timeout_seconds=_env_int("VALIDATION_TIMEOUT_SECONDS", 60),
        revocation_mode=revocation_mode,
        allow_fetching=_env_bool("ALLOW_FETCHING", True),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )
