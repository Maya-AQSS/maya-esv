"""Traduce el estado que devuelve pyHanko a los estados de la API.

Este módulo NO importa pyHanko a propósito: trabaja con atributos del objeto
de estado (``getattr``) para poder probarse de forma aislada.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Optional


class SignatureStatus(str, Enum):
    SIGNED_VALID = "SIGNED_VALID"
    SIGNED_EXPIRED = "SIGNED_EXPIRED"
    SIGNED_REVOKED = "SIGNED_REVOKED"
    SIGNED_INVALID = "SIGNED_INVALID"
    NOT_SIGNED = "NOT_SIGNED"
    APP_ERROR = "APP_ERROR"


@dataclass(frozen=True)
class Verdict:
    status: SignatureStatus
    message: str
    certificate_valid_until: Optional[datetime] = None


def _enum_name(value: Any) -> Optional[str]:
    if value is None:
        return None
    return getattr(value, "name", None) or str(value)


def _as_utc(value: Any) -> Optional[datetime]:
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _cert_not_after(cert: Any) -> Optional[datetime]:
    if cert is None:
        return None
    try:
        return _as_utc(cert.not_valid_after)
    except Exception:  # certificado mal formado
        return None


def classify(status: Any, now: Optional[datetime] = None) -> Verdict:
    """Decide el veredicto de UNA firma a partir del estado de pyHanko.

    pyHanko NO lanza excepciones por certificado revocado o caducado: devuelve
    un objeto de estado con banderas (``intact``, ``valid``, ``trusted``,
    ``revoked``...), que son las que se interpretan aquí.
    """
    now = now or datetime.now(timezone.utc)
    not_after = _cert_not_after(getattr(status, "signing_cert", None))

    def verdict(st: SignatureStatus, msg: str) -> Verdict:
        return Verdict(st, msg, not_after)

    if not getattr(status, "intact", False) or not getattr(status, "valid", False):
        return verdict(
            SignatureStatus.SIGNED_INVALID,
            "La firma no es válida: el contenido firmado ha sido alterado "
            "o la firma está corrupta.",
        )

    if getattr(status, "revoked", False):
        return verdict(
            SignatureStatus.SIGNED_REVOKED,
            "El certificado utilizado para la firma ha sido revocado.",
        )

    if not getattr(status, "trusted", False):
        reference = _as_utc(getattr(status, "validation_time", None)) or now
        if not_after is not None and not_after < reference:
            return verdict(
                SignatureStatus.SIGNED_EXPIRED,
                f"El certificado de la firma caducó el {not_after:%Y-%m-%d}.",
            )
        return verdict(
            SignatureStatus.SIGNED_INVALID,
            "El certificado no es de confianza: emisor desconocido o no se "
            "pudo verificar la cadena de certificación / revocación.",
        )

    coverage = _enum_name(getattr(status, "coverage", None))
    if coverage in {"UNCLEAR", "CONTIGUOUS_BLOCK_FROM_START"}:
        return verdict(
            SignatureStatus.SIGNED_INVALID,
            "La firma no cubre la totalidad del documento.",
        )

    if getattr(status, "docmdp_ok", None) is False:
        return verdict(
            SignatureStatus.SIGNED_INVALID,
            "El documento contiene modificaciones no permitidas por la "
            "política de certificación (DocMDP) de la firma.",
        )

    level = _enum_name(getattr(status, "modification_level", None))
    if level == "OTHER":
        return verdict(
            SignatureStatus.SIGNED_INVALID,
            "El documento fue modificado después de ser firmado.",
        )

    message = "Firma y certificado válidos."
    if level in {"FORM_FILLING", "ANNOTATIONS"}:
        message += (
            " Existen cambios posteriores a la firma permitidos "
            "(relleno de formularios o anotaciones)."
        )
    return verdict(SignatureStatus.SIGNED_VALID, message)


# Prioridad para el estado global: gana el primero que aparezca.
_PRIORITY = (
    SignatureStatus.SIGNED_REVOKED,
    SignatureStatus.SIGNED_EXPIRED,
    SignatureStatus.SIGNED_INVALID,
    SignatureStatus.APP_ERROR,
)


def summarize(statuses: Iterable[SignatureStatus]) -> SignatureStatus:
    found = set(statuses)
    for candidate in _PRIORITY:
        if candidate in found:
            return candidate
    return SignatureStatus.SIGNED_VALID
