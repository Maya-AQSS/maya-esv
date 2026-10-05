"""Validación de las firmas de un PDF con pyHanko."""
from __future__ import annotations

import logging
from datetime import datetime
from io import BytesIO
from typing import Any, List, Optional

from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from .classification import SignatureStatus, classify, summarize
from .config import Settings
from .models import SignatureDetail, ValidationResponse
from .trust_store import TrustMaterial

logger = logging.getLogger(__name__)


class InvalidPdfError(Exception):
    """El fichero no es un PDF legible."""


def _short(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:300]


def _is_doc_timestamp(sig: Any) -> bool:
    """Los sellos de tiempo de documento (DocTimeStamp) no son firmas de personas."""
    try:
        return str(sig.sig_object.get("/SubFilter")) == "/ETSI.RFC3161"
    except Exception:
        return False


def _build_context(material: TrustMaterial, settings: Settings) -> ValidationContext:
    return ValidationContext(
        trust_roots=list(material.trust_roots),
        other_certs=list(material.other_certs),
        allow_fetching=settings.allow_fetching,
        revocation_mode=settings.revocation_mode,
    )


async def _validate_one(sig: Any, context: ValidationContext) -> SignatureDetail:
    field_name = str(getattr(sig, "field_name", None) or "desconocido")
    try:
        status = await async_validate_pdf_signature(
            sig, signer_validation_context=context
        )
    except Exception as exc:
        logger.warning("Error validando la firma '%s'", field_name, exc_info=True)
        return SignatureDetail(
            field_name=field_name,
            status=SignatureStatus.APP_ERROR,
            message=f"No se pudo analizar la firma: {_short(exc)}",
        )

    signer: Optional[str] = None
    cert = getattr(status, "signing_cert", None)
    if cert is not None:
        try:
            signer = cert.subject.human_friendly
        except Exception:
            signer = None
    signing_time = getattr(status, "signer_reported_dt", None)

    verdict = classify(status)
    return SignatureDetail(
        field_name=field_name,
        status=verdict.status,
        signer_name=signer,
        message=verdict.message,
        signing_time=signing_time if isinstance(signing_time, datetime) else None,
        certificate_valid_until=verdict.certificate_valid_until,
    )


async def validate_pdf_bytes(
    data: bytes, material: TrustMaterial, settings: Settings
) -> ValidationResponse:
    try:
        reader = PdfFileReader(BytesIO(data), strict=False)
        signatures: List[Any] = [
            s for s in reader.embedded_signatures if not _is_doc_timestamp(s)
        ]
    except PdfReadError as exc:
        raise InvalidPdfError("El archivo no es un PDF válido o está corrupto.") from exc
    except Exception as exc:
        logger.warning("Fallo inesperado leyendo el PDF", exc_info=True)
        raise InvalidPdfError(
            f"No se pudo leer la estructura del PDF ({_short(exc)})."
        ) from exc

    if not signatures:
        return ValidationResponse(
            is_signed=False, summary_status=SignatureStatus.NOT_SIGNED, details=[]
        )

    # Un contexto por petición: comparte entre firmas las respuestas CRL/OCSP
    # descargadas, pero no acumula información de revocación obsoleta.
    context = _build_context(material, settings)
    details = [await _validate_one(sig, context) for sig in signatures]
    summary = summarize(d.status for d in details)
    logger.info("PDF validado: %d firma(s) -> %s", len(details), summary.value)
    return ValidationResponse(is_signed=True, summary_status=summary, details=details)
