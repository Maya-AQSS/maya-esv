import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

from app.classification import SignatureStatus as S, classify, summarize

NOW = datetime(2026, 10, 5, tzinfo=timezone.utc)


def cert(days_left):
    return NS(not_valid_after=NOW + timedelta(days=days_left))


def status(**kw):
    base = dict(intact=True, valid=True, trusted=True, revoked=False,
                signing_cert=cert(100), coverage=NS(name="ENTIRE_FILE"),
                modification_level=NS(name="NONE"), docmdp_ok=None,
                validation_time=NOW)
    base.update(kw)
    return NS(**base)


class ClassifyTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(classify(status(), NOW).status, S.SIGNED_VALID)

    def test_tampered_content(self):
        self.assertEqual(classify(status(intact=False), NOW).status, S.SIGNED_INVALID)
        self.assertEqual(classify(status(valid=False), NOW).status, S.SIGNED_INVALID)

    def test_revoked(self):
        v = classify(status(revoked=True, trusted=False), NOW)
        self.assertEqual(v.status, S.SIGNED_REVOKED)

    def test_expired_untrusted(self):
        v = classify(status(trusted=False, signing_cert=cert(-5)), NOW)
        self.assertEqual(v.status, S.SIGNED_EXPIRED)

    def test_untrusted_issuer_not_expired(self):
        v = classify(status(trusted=False), NOW)
        self.assertEqual(v.status, S.SIGNED_INVALID)

    def test_cert_expired_but_trusted_at_signing_time_is_valid(self):
        # Con sello de tiempo, pyHanko valida a fecha de sellado y lo da por confiable.
        v = classify(status(signing_cert=cert(-5)), NOW)
        self.assertEqual(v.status, S.SIGNED_VALID)

    def test_modified_after_signing(self):
        v = classify(status(modification_level=NS(name="OTHER"),
                            coverage=NS(name="ENTIRE_REVISION")), NOW)
        self.assertEqual(v.status, S.SIGNED_INVALID)

    def test_allowed_changes_are_valid_with_note(self):
        v = classify(status(modification_level=NS(name="FORM_FILLING"),
                            coverage=NS(name="ENTIRE_REVISION")), NOW)
        self.assertEqual(v.status, S.SIGNED_VALID)
        self.assertIn("cambios posteriores", v.message)

    def test_partial_coverage(self):
        v = classify(status(coverage=NS(name="CONTIGUOUS_BLOCK_FROM_START")), NOW)
        self.assertEqual(v.status, S.SIGNED_INVALID)

    def test_docmdp_violation(self):
        self.assertEqual(classify(status(docmdp_ok=False), NOW).status, S.SIGNED_INVALID)

    def test_naive_datetimes_do_not_crash(self):
        st = status(trusted=False, signing_cert=NS(not_valid_after=datetime(2020, 1, 1)),
                    validation_time=datetime(2026, 1, 1))
        self.assertEqual(classify(st, NOW).status, S.SIGNED_EXPIRED)

    def test_broken_certificate_object(self):
        class Broken:
            @property
            def not_valid_after(self):
                raise ValueError("boom")
        self.assertEqual(classify(status(signing_cert=Broken()), NOW).status, S.SIGNED_VALID)


class SummarizeTests(unittest.TestCase):
    def test_priority(self):
        self.assertEqual(summarize([S.SIGNED_VALID, S.SIGNED_INVALID, S.SIGNED_REVOKED]), S.SIGNED_REVOKED)
        self.assertEqual(summarize([S.SIGNED_VALID, S.SIGNED_EXPIRED, S.SIGNED_INVALID]), S.SIGNED_EXPIRED)
        self.assertEqual(summarize([S.SIGNED_VALID, S.APP_ERROR]), S.APP_ERROR)
        self.assertEqual(summarize([S.SIGNED_VALID, S.SIGNED_VALID]), S.SIGNED_VALID)


if __name__ == "__main__":
    unittest.main()
