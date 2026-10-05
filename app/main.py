import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

from .config import get_settings
from .models import SignatureDetail, SignatureStatus, ValidationResponse
from .trust_store import TrustStore
from .validator import InvalidPdfError, validate_pdf_bytes

logger = logging.getLogger(__name__)
_CHUNK = 1024 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    store = TrustStore(
        settings.certs_dir,
        include_system=settings.use_system_certs,
        refresh_seconds=settings.trust_refresh_seconds,
        expiry_warning_days=settings.expiry_warning_days,
    )
    await store.get()  # precarga: los problemas de certificados salen al arrancar
    app.state.trust_store = store
    yield


app = FastAPI(
    title="Maya | Esv. Servicio de Validación de Firmas PDF",
    version="1.1.0",
    description="API para validar firmas electrónicas en documentos PDF "
    "(integridad, cadena de confianza, caducidad y revocación).",
    lifespan=lifespan,
)


def _error_response(status_code: int, field_name: str, message: str) -> JSONResponse:
    body = ValidationResponse(
        is_signed=False,
        summary_status=SignatureStatus.APP_ERROR,
        details=[SignatureDetail(
            field_name=field_name, status=SignatureStatus.APP_ERROR, message=message
        )],
    )
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


async def _read_pdf(file: UploadFile, max_bytes: int) -> bytes:
    chunks, total = [], 0
    while chunk := await file.read(_CHUNK):
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"El archivo supera el tamaño máximo de {max_bytes // (1024 * 1024)} MB.",
            )
        chunks.append(chunk)
    data = b"".join(chunks)
    # Cabecera PDF (la especificación admite basura en los primeros 1024 bytes).
    if b"%PDF-" not in data[:1024]:
        raise HTTPException(status_code=400, detail="El archivo debe ser un PDF.")
    return data


@app.post(
    "/validate-signature",
    response_model=ValidationResponse,
    responses={
        400: {"description": "El fichero no es un PDF"},
        413: {"description": "Fichero demasiado grande"},
        422: {"model": ValidationResponse, "description": "PDF corrupto o ilegible"},
        500: {"model": ValidationResponse, "description": "Error interno"},
        504: {"model": ValidationResponse, "description": "Tiempo de validación agotado"},
    },
)
async def validate_signature(request: Request, file: UploadFile = File(...)):
    """Valida las firmas electrónicas de un PDF: integridad, confianza,
    caducidad y revocación del certificado, y modificaciones posteriores."""
    settings = get_settings()
    data = await _read_pdf(file, settings.max_upload_bytes)
    material = await request.app.state.trust_store.get()
    try:
        return await asyncio.wait_for(
            validate_pdf_bytes(data, material, settings),
            timeout=settings.validation_timeout_seconds,
        )
    except InvalidPdfError as exc:
        return _error_response(422, "none", str(exc))
    except asyncio.TimeoutError:
        logger.error("Tiempo de validación agotado (%ss)", settings.validation_timeout_seconds)
        return _error_response(
            504, "global",
            "Se agotó el tiempo de validación (posible fallo al consultar CRL/OCSP).",
        )
    except Exception:
        logger.exception("Error inesperado validando el documento")
        return _error_response(500, "global", "Error interno validando el documento.")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/trust-store")
async def trust_store_info(request: Request):
    """Resumen del almacén de confianza cargado (para mantenimiento)."""
    material = await request.app.state.trust_store.get()
    return material.summary
