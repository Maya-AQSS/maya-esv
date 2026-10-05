import asyncio
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import asn1crypto  # noqa: F401
    HAVE_ASN1 = True
except ImportError:  # pragma: no cover
    HAVE_ASN1 = False

from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_cert(cn, issuer_cn=None, days=365, ca=False):
    """Genera un certificado de prueba (autofirmado si issuer_cn es None)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    cert = (
        cx509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key()).serial_number(cx509.random_serial_number())
        .not_valid_before(now - timedelta(days=10))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(cx509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


@unittest.skipUnless(HAVE_ASN1, "asn1crypto no instalado (viene con pyhanko)")
class TrustStoreTests(unittest.TestCase):
    def setUp(self):
        from app.trust_store import TrustStore
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.make_store = lambda **kw: TrustStore(self.dir, include_system=False, **kw)

    def tearDown(self):
        self.tmp.cleanup()

    def load(self, store):
        return asyncio.run(store.get())

    def test_roots_vs_auxiliary_and_formats(self):
        (self.dir / "root.cer").write_bytes(pem(make_cert("Root", ca=True)))       # PEM con .cer
        (self.dir / "Con Espacios.crt").write_bytes(der(make_cert("Root DER", ca=True)))  # DER
        (self.dir / "ocsp.cer").write_bytes(pem(make_cert("OCSP", "Root")))        # no autofirmado
        (self.dir / "notas.txt").write_text("no es un certificado")
        (self.dir / "basura.pem").write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
        m = self.load(self.make_store())
        self.assertEqual(len(m.trust_roots), 2)
        self.assertEqual(len(m.other_certs), 1)
        self.assertTrue(any("basura.pem" in w for w in m.summary["warnings"]))

    def test_duplicates_are_ignored(self):
        c = make_cert("Root", ca=True)
        (self.dir / "a.crt").write_bytes(pem(c))
        (self.dir / "b.cer").write_bytes(der(c))
        self.assertEqual(len(self.load(self.make_store()).trust_roots), 1)

    def test_expiry_warnings(self):
        (self.dir / "caducado.crt").write_bytes(pem(make_cert("Old", days=-1, ca=True)))
        (self.dir / "pronto.crt").write_bytes(pem(make_cert("Soon", days=5, ca=True)))
        (self.dir / "ok.crt").write_bytes(pem(make_cert("Fine", days=900, ca=True)))
        w = " | ".join(self.load(self.make_store()).summary["warnings"])
        self.assertIn("caducado.crt: CADUCADO", w)
        self.assertIn("pronto.crt: caduca", w)
        self.assertNotIn("ok.crt", w)

    def test_reload_when_directory_changes(self):
        (self.dir / "a.crt").write_bytes(pem(make_cert("A", ca=True)))
        store = self.make_store(refresh_seconds=10**6)

        async def scenario():
            first = await store.get()
            again = await store.get()
            (self.dir / "b.crt").write_bytes(pem(make_cert("B", ca=True)))
            third = await store.get()
            return first, again, third

        first, again, third = asyncio.run(scenario())
        self.assertIs(first, again)          # sin cambios: se reutiliza la caché
        self.assertEqual(len(third.trust_roots), 2)

    def test_missing_directory_does_not_crash(self):
        from app.trust_store import TrustStore
        store = TrustStore(self.dir / "no_existe", include_system=False)
        self.assertEqual(len(self.load(store).trust_roots), 0)


if __name__ == "__main__":
    unittest.main()
