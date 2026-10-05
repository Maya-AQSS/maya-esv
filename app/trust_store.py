"""Almacén de certificados de confianza: certificados del SO + carpeta ``certs``.

* Los certificados del sistema operativo se consideran raíces de confianza.
* En ``certs/`` se aceptan ficheros .crt / .cer / .pem / .der (PEM o DER, uno o
  varios certificados por fichero):
    - autofirmados (raíces)  -> raíces de confianza
    - el resto (intermedias, respondedores OCSP...) -> certificados auxiliares
      que ayudan a construir cadenas y a verificar respuestas OCSP, pero que
      NO son anclas de confianza.
* El almacén se carga una vez y se recarga solo cuando cambia el contenido de
  ``certs/`` o transcurre ``refresh_seconds``.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from asn1crypto import pem, x509

logger = logging.getLogger(__name__)

CERT_EXTENSIONS = {".crt", ".cer", ".pem", ".der"}
_PEM_TYPES = {"CERTIFICATE", "TRUSTED CERTIFICATE"}
_WELL_KNOWN_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",  # Debian / Ubuntu / Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",    # RHEL / CentOS / Fedora
    "/etc/ssl/ca-bundle.pem",              # openSUSE
    "/etc/ssl/cert.pem",                   # macOS / BSD / Alpine
)
_MACOS_KEYCHAIN = "/System/Library/Keychains/SystemRootCertificates.keychain"


@dataclass(frozen=True)
class TrustMaterial:
    trust_roots: Tuple[x509.Certificate, ...]
    other_certs: Tuple[x509.Certificate, ...]
    summary: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Lectura de certificados
# --------------------------------------------------------------------------- #
def parse_certs(data: bytes) -> List[x509.Certificate]:
    """Extrae certificados de bytes PEM (uno o varios) o DER."""
    found: List[x509.Certificate] = []
    if pem.detect(data):
        candidates = [
            der for type_name, _, der in pem.unarmor(data, multiple=True)
            if type_name in _PEM_TYPES  # ignora claves privadas, CRL, etc.
        ]
    else:
        candidates = [data]
    for der in candidates:
        try:
            cert = x509.Certificate.load(der)
            cert.not_valid_after  # fuerza el parseo; falla si no es un certificado
            found.append(cert)
        except Exception:
            logger.debug("Se ignora un bloque que no es un certificado X.509 válido")
    return found


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.dump()).hexdigest()


def _subject(cert: x509.Certificate) -> str:
    try:
        return cert.subject.human_friendly
    except Exception:
        return "<desconocido>"


# --------------------------------------------------------------------------- #
# Certificados del sistema operativo
# --------------------------------------------------------------------------- #
def read_system_certs() -> List[x509.Certificate]:
    if sys.platform == "win32":
        return _read_windows_store()
    if sys.platform == "darwin":
        certs = _read_macos_keychain()
        if certs:
            return certs
    return _read_pem_locations()


def _read_windows_store() -> List[x509.Certificate]:
    certs: List[x509.Certificate] = []
    for der, encoding, _trust in ssl.enum_certificates("ROOT"):  # type: ignore[attr-defined]
        if encoding == "x509_asn":
            certs.extend(parse_certs(der))
    return certs


def _read_macos_keychain() -> List[x509.Certificate]:
    try:
        out = subprocess.run(
            ["security", "find-certificate", "-a", "-p", _MACOS_KEYCHAIN],
            capture_output=True, timeout=30, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_certs(out)


def _read_pem_locations() -> List[x509.Certificate]:
    """Linux/BSD: bundle PEM del sistema; si no existe, directorio de certificados."""
    paths = ssl.get_default_verify_paths()
    bundles = [os.environ.get("SSL_CERT_FILE"), paths.cafile, paths.openssl_cafile,
               *_WELL_KNOWN_BUNDLES]
    for candidate in bundles:
        if candidate and os.path.isfile(candidate):
            certs = parse_certs(Path(candidate).read_bytes())
            if certs:
                return certs

    directories = [*(os.environ.get("SSL_CERT_DIR", "").split(os.pathsep)),
                   paths.capath, paths.openssl_capath]
    certs: List[x509.Certificate] = []
    for directory in directories:
        if directory and os.path.isdir(directory):
            for entry in sorted(Path(directory).iterdir()):
                if entry.is_file():
                    certs.extend(parse_certs(entry.read_bytes()))
            if certs:
                break
    return certs


# --------------------------------------------------------------------------- #
# Almacén con caché y recarga
# --------------------------------------------------------------------------- #
class TrustStore:
    def __init__(self, certs_dir: Path, include_system: bool = True,
                 refresh_seconds: int = 3600, expiry_warning_days: int = 30) -> None:
        self._certs_dir = Path(certs_dir)
        self._include_system = include_system
        self._refresh_seconds = refresh_seconds
        self._warning_days = expiry_warning_days
        self._material: Optional[TrustMaterial] = None
        self._signature: Tuple = ()
        self._loaded_at = 0.0
        self._lock = asyncio.Lock()

    def _local_files(self) -> List[Path]:
        if not self._certs_dir.is_dir():
            return []
        return sorted(
            p for p in self._certs_dir.iterdir()
            if p.is_file() and p.suffix.lower() in CERT_EXTENSIONS
        )

    def _dir_signature(self) -> Tuple:
        signature = []
        for path in self._local_files():
            try:
                st = path.stat()
            except OSError:
                continue
            signature.append((path.name, st.st_mtime_ns, st.st_size))
        return tuple(signature)

    def _is_stale(self) -> bool:
        return (
            self._material is None
            or time.monotonic() - self._loaded_at > self._refresh_seconds
            or self._dir_signature() != self._signature
        )

    async def get(self) -> TrustMaterial:
        if not self._is_stale():
            return self._material  # type: ignore[return-value]
        async with self._lock:
            if self._is_stale():
                signature = self._dir_signature()
                try:
                    self._material = await asyncio.to_thread(self._build)
                except Exception:
                    logger.exception("No se pudo (re)cargar el almacén de confianza")
                    if self._material is None:
                        raise
                self._signature = signature
                self._loaded_at = time.monotonic()
            return self._material  # type: ignore[return-value]

    def _build(self) -> TrustMaterial:
        started = time.monotonic()
        seen: set = set()
        roots: List[x509.Certificate] = []
        others: List[x509.Certificate] = []
        warnings: List[str] = []

        if self._include_system:
            try:
                for cert in read_system_certs():
                    fp = fingerprint(cert)
                    if fp not in seen:
                        seen.add(fp)
                        roots.append(cert)
            except Exception:
                logger.exception("No se pudieron leer los certificados del sistema operativo")
        system_count = len(roots)

        now = datetime.now(timezone.utc)
        limit = now + timedelta(days=self._warning_days)
        local_info: List[Dict[str, Any]] = []
        for path in self._local_files():
            try:
                certs = parse_certs(path.read_bytes())
            except OSError as exc:
                warnings.append(f"{path.name}: no se puede leer ({exc})")
                continue
            if not certs:
                warnings.append(f"{path.name}: no contiene ningún certificado X.509 válido")
                continue
            for cert in certs:
                is_root = cert.self_signed != "no"
                not_after = cert.not_valid_after
                expired = not_after < now
                if expired:
                    warnings.append(f"{path.name}: CADUCADO el {not_after:%Y-%m-%d}")
                elif not_after < limit:
                    warnings.append(f"{path.name}: caduca el {not_after:%Y-%m-%d}")
                local_info.append({
                    "file": path.name,
                    "subject": _subject(cert),
                    "role": "trust_root" if is_root else "auxiliary",
                    "valid_until": not_after.isoformat(),
                    "expired": expired,
                })
                fp = fingerprint(cert)
                if fp in seen:
                    continue
                seen.add(fp)
                (roots if is_root else others).append(cert)

        for warning in warnings:
            logger.warning("certs/: %s", warning)
        summary = {
            "system_roots": system_count,
            "local_roots": len(roots) - system_count,
            "local_auxiliary": len(others),
            "certs_dir": str(self._certs_dir),
            "local_certificates": local_info,
            "warnings": warnings,
            "loaded_at": now.isoformat(),
        }
        logger.info(
            "Almacén de confianza cargado en %.2fs: %d raíces del SO, %d raíces locales, "
            "%d auxiliares locales",
            time.monotonic() - started, system_count, summary["local_roots"], len(others),
        )
        if not roots:
            logger.error("El almacén de confianza está VACÍO: ninguna firma será de confianza")
        return TrustMaterial(tuple(roots), tuple(others), summary)
