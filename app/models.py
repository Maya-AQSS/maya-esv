from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from .classification import SignatureStatus

__all__ = ["SignatureStatus", "SignatureDetail", "ValidationResponse"]


class SignatureDetail(BaseModel):
    field_name: str
    status: SignatureStatus
    signer_name: Optional[str] = None
    message: str
    signing_time: Optional[datetime] = Field(
        default=None, description="Fecha de firma declarada por el firmante (no es un sello de tiempo)."
    )
    certificate_valid_until: Optional[datetime] = Field(
        default=None, description="Fecha de caducidad del certificado de firma."
    )


class ValidationResponse(BaseModel):
    is_signed: bool
    summary_status: SignatureStatus
    details: List[SignatureDetail]
