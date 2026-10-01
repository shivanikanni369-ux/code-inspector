"""Tests for the REST API.  Run with:  python manage.py test"""
import io
import urllib.error
import zipfile
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from scanner.models import Scan

User = get_user_model()
WEAK_HASH_CODE = "import hashlib\n\n\ndef h(p):\n    return hashlib.md5(p.encode()).hexdigest()\n"
PASSWORD = "a-long-Passw0rd-123"


class ApiTests(APITestCase):
    def setUp(self):
        cache.clear()  # rate-limit counters live in the cache
        self.user = User.objects.create_user(username="alice", password=PASSWORD)
        self.client.force_authenticate(self.user)

    def test_requires_authentication(self):
        self.client.force_authenticate(None)
        for url in ("/api/scans/", "/api/rules/"):
            with self.subTest(url=url):
                self.assertIn(self.client.get(url).status_code, (401, 403))

    def test_basic_auth_works_like_postman(self):
        self.client.force_authenticate(None)
        self.client.credentials(HTTP_AUTHORIZATION="Basic YWxpY2U6YS1sb25nLVBhc3N3MHJkLTEyMw==")  # alice:a-long-Passw0rd-123
        self.assertEqual(self.client.get("/api/scans/").status_code, 200)

    def test_token_auth_and_obtain_endpoint(self):
        self.client.force_authenticate(None)
        obtained = self.client.post("/api/token/", {"username": "alice", "password": PASSWORD})
        self.assertEqual(obtained.status_code, 200)
        token_key = obtained.json()["token"]
        self.assertEqual(token_key, Token.objects.get(user=self.user).key)

        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token_key}")
        self.assertEqual(self.client.get("/api/scans/").status_code, 200)

        self.client.credentials(HTTP_AUTHORIZATION="Token not-a-real-token")
        self.assertEqual(self.client.get("/api/scans/").status_code, 401)

    def test_create_scan_from_json(self):
        response = self.client.post(
            "/api/scans/", {"filename": "auth.py", "code": WEAK_HASH_CODE, "name": "API demo"}, format="json"
        )
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["name"], "API demo")
        self.assertEqual(body["medium_count"], 1)
        self.assertEqual(body["issues"][0]["rule_id"], "PY-WEAK-HASH")
        self.assertEqual(Scan.objects.filter(owner=self.user).count(), 1)

    def test_create_scan_from_zip_upload(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("app.py", WEAK_HASH_CODE)
        upload = SimpleUploadedFile("project.zip", buffer.getvalue(), content_type="application/zip")
        response = self.client.post("/api/scans/", {"upload": upload}, format="multipart")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["name"], "project.zip")

    def test_create_scan_from_github_repo_url(self):
        # No real network call: urlopen is mocked so this test is fast and offline.
        zip_bytes = io.BytesIO()
        with zipfile.ZipFile(zip_bytes, "w") as archive:
            archive.writestr("app.py", WEAK_HASH_CODE)

        class FakeResponse:
            def __init__(self, data):
                self._data = data

            def read(self, _n):
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(request, timeout):
            return FakeResponse(zip_bytes.getvalue())

        with mock.patch("scanner.analyzer.ingest.urllib.request.urlopen", fake_urlopen):
            response = self.client.post(
                "/api/scans/", {"repo_url": "https://github.com/someone/somerepo"}, format="json"
            )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["name"], "somerepo")
        self.assertEqual(response.json()["medium_count"], 1)

    def test_create_scan_from_invalid_github_url_returns_400(self):
        response = self.client.post("/api/scans/", {"repo_url": "https://example.com/not/github"}, format="json")
        self.assertEqual(response.status_code, 400)

    def test_bad_requests_return_400(self):
        self.assertEqual(self.client.post("/api/scans/", {}, format="json").status_code, 400)
        both = {"code": WEAK_HASH_CODE, "upload": SimpleUploadedFile("a.py", b"x = 1\n")}
        self.assertEqual(self.client.post("/api/scans/", both, format="multipart").status_code, 400)
        bad_zip = SimpleUploadedFile("x.zip", b"not a zip")
        self.assertEqual(self.client.post("/api/scans/", {"upload": bad_zip}, format="multipart").status_code, 400)
        self.assertEqual(Scan.objects.count(), 0)

    def test_list_retrieve_and_delete(self):
        created = self.client.post("/api/scans/", {"code": WEAK_HASH_CODE}, format="json").json()
        listing = self.client.get("/api/scans/").json()
        self.assertEqual(listing["count"], 1)
        self.assertNotIn("issues", listing["results"][0])
        detail = self.client.get(f"/api/scans/{created['id']}/").json()
        self.assertEqual(len(detail["issues"]), 1)
        self.assertEqual(self.client.delete(f"/api/scans/{created['id']}/").status_code, 204)
        self.assertEqual(Scan.objects.count(), 0)

    def test_users_only_see_their_own_scans(self):
        created = self.client.post("/api/scans/", {"code": WEAK_HASH_CODE}, format="json").json()
        self.client.force_authenticate(User.objects.create_user(username="bob", password=PASSWORD))
        self.assertEqual(self.client.get("/api/scans/").json()["count"], 0)
        self.assertEqual(self.client.get(f"/api/scans/{created['id']}/").status_code, 404)
        self.assertEqual(self.client.delete(f"/api/scans/{created['id']}/").status_code, 404)
        self.assertEqual(Scan.objects.count(), 1)

    def test_rules_catalogue(self):
        rules = self.client.get("/api/rules/").json()
        self.assertTrue(any(r["id"] == "PY-SQLI" for r in rules))

    def test_pdf_report_action(self):
        created = self.client.post("/api/scans/", {"code": WEAK_HASH_CODE}, format="json").json()
        response = self.client.get(f"/api/scans/{created['id']}/report.pdf")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertTrue(response.content.startswith(b"%PDF-"))

    def test_pdf_report_action_is_private_to_the_owner(self):
        created = self.client.post("/api/scans/", {"code": WEAK_HASH_CODE}, format="json").json()
        self.client.force_authenticate(User.objects.create_user(username="bob", password=PASSWORD))
        self.assertEqual(self.client.get(f"/api/scans/{created['id']}/report.pdf").status_code, 404)
