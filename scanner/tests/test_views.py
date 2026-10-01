"""Tests for the web layer.  Run with:  python manage.py test"""
import io
import zipfile

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from scanner.models import Scan

User = get_user_model()

WEAK_HASH_CODE = "import hashlib\n\n\ndef h(p):\n    return hashlib.md5(p.encode()).hexdigest()\n"


def make_user(name="alice"):
    return User.objects.create_user(username=name, password="a-long-Passw0rd-123")


class AccessTests(TestCase):
    def test_pages_require_login(self):
        for name in ("dashboard", "new_scan"):
            with self.subTest(page=name):
                response = self.client.get(reverse(name))
                self.assertEqual(response.status_code, 302)
                self.assertIn(reverse("login"), response["Location"])

    def test_signup_creates_account_and_logs_in(self):
        response = self.client.post(reverse("signup"), {
            "username": "newuser", "password1": "a-long-Passw0rd-123", "password2": "a-long-Passw0rd-123",
        })
        self.assertRedirects(response, reverse("dashboard"))
        self.assertTrue(User.objects.filter(username="newuser").exists())


class ScanFlowTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.client.force_login(self.user)

    def test_pasted_code_is_scanned_and_saved(self):
        response = self.client.post(reverse("new_scan"), {"code": WEAK_HASH_CODE, "filename": "auth.py", "name": "Demo"})
        scan = Scan.objects.get(owner=self.user)
        self.assertRedirects(response, reverse("scan_detail", args=[scan.pk]))
        self.assertEqual(scan.name, "Demo")
        self.assertTrue(scan.issues.filter(rule_id="PY-WEAK-HASH", file_path="auth.py").exists())
        self.assertEqual(scan.medium_count, 1)

    def test_zip_upload(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("proj/app.py", WEAK_HASH_CODE)
            archive.writestr("proj/.env", "SECRET_KEY=abcdef123456\n")
        upload = SimpleUploadedFile("proj.zip", buffer.getvalue(), content_type="application/zip")
        self.client.post(reverse("new_scan"), {"upload": upload})
        scan = Scan.objects.get(owner=self.user)
        self.assertEqual(scan.files_scanned, 2)
        rules = set(scan.issues.values_list("rule_id", flat=True))
        self.assertTrue({"PY-WEAK-HASH", "SEC-SECRET", "SEC-ENV-FILE"} <= rules)

    def test_empty_and_invalid_submissions_show_errors(self):
        empty = self.client.post(reverse("new_scan"), {"code": "   "})
        self.assertEqual(empty.status_code, 200)
        self.assertContains(empty, "Paste some code OR upload")
        bad = self.client.post(reverse("new_scan"), {"upload": SimpleUploadedFile("x.zip", b"not a zip")})
        self.assertContains(bad, "valid ZIP")
        self.assertEqual(Scan.objects.count(), 0)

    def test_detail_filter_and_json_report(self):
        self.client.post(reverse("new_scan"), {"code": WEAK_HASH_CODE + "import os\n"})
        scan = Scan.objects.get()
        detail = self.client.get(reverse("scan_detail", args=[scan.pk]), {"severity": "medium"})
        self.assertContains(detail, "Weak hash algorithm")
        self.assertNotContains(detail, "Unused import")
        report = self.client.get(reverse("scan_json", args=[scan.pk]))
        self.assertEqual(report.status_code, 200)
        self.assertIn("attachment", report["Content-Disposition"])
        self.assertEqual(report.json()["counts"]["medium"], 1)

    def test_pdf_report(self):
        self.client.post(reverse("new_scan"), {"code": WEAK_HASH_CODE})
        scan = Scan.objects.get()
        report = self.client.get(reverse("scan_pdf", args=[scan.pk]))
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report["Content-Type"], "application/pdf")
        self.assertIn("attachment", report["Content-Disposition"])
        self.assertTrue(report.content.startswith(b"%PDF-"))

    def test_pdf_report_with_no_issues(self):
        self.client.post(reverse("new_scan"), {"code": "x = 1\n"})
        scan = Scan.objects.get()
        report = self.client.get(reverse("scan_pdf", args=[scan.pk]))
        self.assertEqual(report.status_code, 200)
        self.assertTrue(report.content.startswith(b"%PDF-"))

    def test_delete_needs_post(self):
        self.client.post(reverse("new_scan"), {"code": WEAK_HASH_CODE})
        scan = Scan.objects.get()
        self.assertEqual(self.client.get(reverse("scan_delete", args=[scan.pk])).status_code, 405)
        self.assertEqual(Scan.objects.count(), 1)
        self.client.post(reverse("scan_delete", args=[scan.pk]))
        self.assertEqual(Scan.objects.count(), 0)


class PrivacyTests(TestCase):
    def test_users_cannot_open_or_delete_each_others_scans(self):
        owner, other = make_user("owner"), make_user("other")
        self.client.force_login(owner)
        self.client.post(reverse("new_scan"), {"code": WEAK_HASH_CODE})
        scan = Scan.objects.get()

        self.client.force_login(other)
        for name in ("scan_detail", "scan_json", "scan_pdf"):
            with self.subTest(page=name):
                self.assertEqual(self.client.get(reverse(name, args=[scan.pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse("scan_delete", args=[scan.pk])).status_code, 404)
        self.assertTrue(Scan.objects.filter(pk=scan.pk).exists())
        self.assertNotContains(self.client.get(reverse("dashboard")), scan.name)
