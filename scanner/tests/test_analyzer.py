"""Tests for the analysis engine. Plain unittest, so no Django is needed to run them:

    python -m unittest scanner.tests.test_analyzer
"""
import io
import textwrap
import unittest
import unittest.mock
import urllib.error
import zipfile

from scanner.analyzer import IngestError, compute_score, read_upload, scan_files, scan_source
from scanner.analyzer import ingest


def rule_ids(source, path="app.py"):
    return {issue.rule_id for issue in scan_source(path, textwrap.dedent(source))}


def issues_for(source, path="app.py"):
    return scan_source(path, textwrap.dedent(source))


class SecurityRuleTests(unittest.TestCase):
    def test_eval_with_variable_is_flagged_but_constant_is_not(self):
        self.assertIn("PY-EVAL", rule_ids("def f(x):\n    return eval(x)\n"))
        self.assertNotIn("PY-EVAL", rule_ids("value = eval('1 + 1')\n"))

    def test_shell_true_is_flagged_even_through_an_alias(self):
        self.assertIn("PY-SHELL", rule_ids("import subprocess\nsubprocess.run(cmd, shell=True)\n"))
        self.assertIn("PY-SHELL", rule_ids("import subprocess as sp\nsp.call(cmd, shell=True)\n"))
        self.assertIn("PY-SHELL", rule_ids("from os import system\nsystem(cmd)\n"))

    def test_safe_subprocess_and_constant_os_system(self):
        self.assertNotIn("PY-SHELL", rule_ids("import subprocess\nsubprocess.run(['ls', '-l'])\n"))
        self.assertNotIn("PY-SHELL", rule_ids("import os\nos.system('clear')\n"))

    def test_constant_shell_true_is_only_medium(self):
        issue = issues_for("import subprocess\nsubprocess.run('ls', shell=True)\n")[0]
        self.assertEqual(issue.severity, "MEDIUM")

    def test_sql_injection_patterns(self):
        for snippet in (
            'cur.execute(f"SELECT * FROM t WHERE id = {uid}")',
            'cur.execute("SELECT * FROM t WHERE name = \'" + name + "\'")',
            'cur.execute("SELECT * FROM t WHERE id = %s" % uid)',
            'cur.execute("SELECT * FROM t WHERE id = {}".format(uid))',
            'Model.objects.raw(f"SELECT * FROM t WHERE id = {uid}")',
        ):
            with self.subTest(snippet=snippet):
                self.assertIn("PY-SQLI", rule_ids(snippet + "\n"))

    def test_parameterized_sql_is_not_flagged(self):
        self.assertNotIn("PY-SQLI", rule_ids('cur.execute("SELECT * FROM t WHERE id = %s", [uid])\n'))
        self.assertNotIn("PY-SQLI", rule_ids('cur.execute("SELECT * FROM t")\n'))
        self.assertNotIn("PY-SQLI", rule_ids('log.debug(f"loaded {count} rows from cache")\n'))

    def test_hardcoded_secrets(self):
        for snippet in (
            'DB_PASSWORD = "hunter2-real"',
            'api_key = "abcdef123456"',
            'connect(host="db", password="s3cr3tvalue")',
            'CONFIG = {"secret": "abcdef123456"}',
            'SECRET_KEY = "django-insecure-abc123"',
        ):
            with self.subTest(snippet=snippet):
                self.assertIn("PY-SECRET", rule_ids(snippet + "\n"))

    def test_secret_value_is_masked_in_the_report(self):
        issue = issues_for('DB_PASSWORD = "hunter2-real"\n')[0]
        self.assertNotIn("hunter2", issue.snippet)
        self.assertIn("****", issue.snippet)

    def test_secrets_in_test_files_are_low_severity(self):
        issue = issues_for('password = "hunter2-fake"\n', path="app/tests/test_login.py")[0]
        self.assertEqual((issue.rule_id, issue.severity), ("PY-SECRET", "LOW"))

    def test_things_that_are_not_secrets(self):
        for snippet in (
            'PASSWORD_FIELD = "password"',
            'password = os.environ["DB_PASSWORD"]',
            'API_KEY = ""',
            'token_url = "https://example.com/oauth/token"',
            'password = "<your-password-here>"',
            'error_message = "Wrong password, try again"',
            'tokenizer = "bert-base-uncased"',
            'SECRET_WORDS = "secret|token|password"',
        ):
            with self.subTest(snippet=snippet):
                self.assertNotIn("PY-SECRET", rule_ids("import os\n" + snippet + "\n"))

    def test_weak_hashes(self):
        self.assertIn("PY-WEAK-HASH", rule_ids("import hashlib\nhashlib.md5(b'x')\n"))
        self.assertIn("PY-WEAK-HASH", rule_ids("from hashlib import sha1\nsha1(b'x')\n"))
        self.assertNotIn("PY-WEAK-HASH", rule_ids("import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n"))
        self.assertNotIn("PY-WEAK-HASH", rule_ids("import hashlib\nhashlib.sha256(b'x')\n"))

    def test_unsafe_deserialization(self):
        self.assertIn("PY-DESERIALIZE", rule_ids("import pickle\npickle.loads(blob)\n"))
        self.assertIn("PY-DESERIALIZE", rule_ids("import yaml\nyaml.load(text)\n"))
        self.assertNotIn("PY-DESERIALIZE", rule_ids("import yaml\nyaml.safe_load(text)\n"))
        self.assertNotIn("PY-DESERIALIZE", rule_ids("import yaml\nyaml.load(text, Loader=yaml.SafeLoader)\n"))

    def test_debug_hosts_and_tls(self):
        self.assertIn("PY-DEBUG", rule_ids("DEBUG = True\n"))
        self.assertIn("PY-DEBUG", rule_ids("app.run(debug=True)\n"))
        self.assertNotIn("PY-DEBUG", rule_ids("DEBUG = False\n"))
        self.assertIn("PY-HOSTS", rule_ids("ALLOWED_HOSTS = ['*']\n"))
        self.assertNotIn("PY-HOSTS", rule_ids("ALLOWED_HOSTS = ['example.com']\n"))
        self.assertIn("PY-TLS-OFF", rule_ids("import requests\nrequests.get(url, verify=False)\n"))

    def test_tempfile_and_chmod(self):
        self.assertIn("PY-TEMPFILE", rule_ids("import tempfile\ntempfile.mktemp()\n"))
        self.assertIn("PY-CHMOD", rule_ids("import os\nos.chmod(p, 0o777)\n"))
        self.assertNotIn("PY-CHMOD", rule_ids("import os\nos.chmod(p, 0o600)\n"))


class GenericRuleTests(unittest.TestCase):
    def test_aws_key_is_found_and_masked(self):
        issue = issues_for('const k = "' + "AKIA" + 'IOSFODNN7EXAMPLE";\n', path="config.js")[0]
        self.assertEqual(issue.rule_id, "SEC-AWS-KEY")
        self.assertNotIn("IOSFODNN7EXAMPLE", issue.snippet)

    def test_private_key_header(self):
        self.assertIn("SEC-PRIVATE-KEY", rule_ids("-----BEGIN RSA " + "PRIVATE KEY-----\n", path="deploy.sh"))

    def test_env_file(self):
        found = rule_ids("SECRET_KEY=abcdef123456\nAPI_TOKEN=<your-token>\n", path=".env")
        self.assertIn("SEC-ENV-FILE", found)
        self.assertIn("SEC-SECRET", found)
        self.assertNotIn("SEC-ENV-FILE", rule_ids("A=1\n", path=".env.example"))
        placeholder_only = rule_ids("API_TOKEN=<your-token>\n", path=".env.example")
        self.assertNotIn("SEC-SECRET", placeholder_only)

    def test_javascript_rules(self):
        self.assertIn("WEB-EVAL", rule_ids("const r = eval(input);\n", path="a.js"))
        self.assertIn("WEB-INNERHTML", rule_ids("el.innerHTML = userText;\n", path="a.js"))
        self.assertIn("WEB-DOCWRITE", rule_ids("document.write(x);\n", path="a.html"))
        self.assertNotIn("WEB-EVAL", rule_ids("// eval(x) is dangerous\n", path="a.js"))
        self.assertNotIn("WEB-EVAL", rule_ids("const r = medieval(x);\n", path="a.js"))

    def test_js_secret_with_camel_case_url_name_is_ignored(self):
        self.assertIn("SEC-SECRET", rule_ids('const apiKey = "abcdef123456";\n', path="a.js"))
        self.assertNotIn("SEC-SECRET", rule_ids('const tokenUrl = "abcdef123456";\n', path="a.js"))


class QualityRuleTests(unittest.TestCase):
    def test_unused_import(self):
        self.assertIn("Q-UNUSED-IMPORT", rule_ids("import os\n"))
        self.assertNotIn("Q-UNUSED-IMPORT", rule_ids("import os\nprint(os.getcwd())\n"))
        self.assertNotIn("Q-UNUSED-IMPORT", rule_ids("import os.path\nprint(os.getcwd())\n"))
        self.assertNotIn("Q-UNUSED-IMPORT", rule_ids("import os\n", path="pkg/__init__.py"))
        self.assertNotIn("Q-UNUSED-IMPORT", rule_ids("from __future__ import annotations\n"))

    def test_boolean_operators_do_not_count_as_branches(self):
        self.assertNotIn("Q-COMPLEX", rule_ids("def f(a, b, c, d):\n    return a and b and c and d and a or b or c or d\n"))

    def test_complexity_and_length_and_args(self):
        branches = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(12))
        self.assertIn("Q-COMPLEX", rule_ids(f"def f(x):\n{branches}    return None\n"))
        body = "".join(f"    y{i} = {i}\n" for i in range(60))
        self.assertIn("Q-LONG-FUNC", rule_ids(f"def f():\n{body}"))
        self.assertIn("Q-MANY-ARGS", rule_ids("def f(a, b, c, d, e, f, g, h):\n    pass\n"))
        self.assertNotIn("Q-MANY-ARGS", rule_ids("class A:\n    def m(self, a, b, c, d, e, f, g):\n        pass\n"))

    def test_mutable_default_and_broad_except(self):
        self.assertIn("Q-MUTABLE-DEFAULT", rule_ids("def f(x=[]):\n    pass\n"))
        self.assertNotIn("Q-MUTABLE-DEFAULT", rule_ids("def f(x=None):\n    pass\n"))
        self.assertIn("Q-BARE-EXCEPT", rule_ids("try:\n    x = 1\nexcept:\n    x = 2\n"))
        self.assertIn("Q-BARE-EXCEPT", rule_ids("try:\n    x = 1\nexcept Exception:\n    pass\n"))
        self.assertNotIn("Q-BARE-EXCEPT", rule_ids("try:\n    import json\nexcept ImportError:\n    pass\n"))

    def test_syntax_error_is_reported_not_raised(self):
        self.assertIn("Q-SYNTAX", rule_ids("def broken(:\n    pass\n"))

    def test_clean_file_has_no_issues(self):
        clean = '''
            import os


            def read_setting(name, default=None):
                """Read a setting from the environment."""
                return os.environ.get(name, default)
        '''
        self.assertEqual(issues_for(clean), [])


class ScoringTests(unittest.TestCase):
    def test_clean_project_scores_100(self):
        report = scan_files([("ok.py", "x = 1\n")])
        self.assertEqual((report.score, report.grade), (100, "A"))

    def test_serious_problems_lower_the_grade(self):
        report = scan_files([("bad.py", "DEBUG = True\nDB_PASSWORD = 'hunter2-real'\ncur.execute(f'SELECT {x} FROM t')\n")])
        self.assertLess(report.score, 90)
        self.assertEqual(report.counts["HIGH"], 2)

    def test_one_noisy_rule_cannot_zero_the_score(self):
        imports = "".join(f"import mod{i}\n" for i in range(40))
        report = scan_files([("noisy.py", imports)])
        self.assertEqual(report.counts["LOW"], 40)
        self.assertGreaterEqual(report.score, 95)

    def test_duplicates_are_removed_and_results_sorted(self):
        report = scan_files([("a.py", "import os\nDEBUG = True\n"), ("a.py", "import os\nDEBUG = True\n")])
        self.assertEqual(len(report.issues), 2)
        self.assertEqual(report.issues[0].severity, "MEDIUM")
        self.assertEqual(compute_score([]), 100)


def make_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class IngestTests(unittest.TestCase):
    def test_single_file_and_bad_types(self):
        self.assertEqual(read_upload("a.py", b"x = 1\n"), [("a.py", "x = 1\n")])
        with self.assertRaises(IngestError):
            read_upload("photo.png", b"\x89PNG")
        with self.assertRaises(IngestError):
            read_upload("a.py", b"\x00\x01\x02binary")
        with self.assertRaises(IngestError):
            read_upload("big.py", b"x" * (ingest.MAX_FILE_BYTES + 1))

    def test_zip_keeps_source_and_skips_junk(self):
        data = make_zip({
            "proj/app.py": "x = 1\n",
            "proj/node_modules/lib/a.js": "var a;\n",
            "proj/.git/config": "[core]\n",
            "proj/logo.png": "binary",
            "../evil.py": "x = 1\n",
            "/abs/evil.py": "x = 1\n",
            "proj/.env": "SECRET_KEY=abcdef123456\n",
        })
        paths = sorted(path for path, _ in read_upload("project.zip", data))
        self.assertEqual(paths, ["abs/evil.py", "proj/.env", "proj/app.py"])

    def test_invalid_zip_is_rejected(self):
        with self.assertRaises(IngestError):
            read_upload("x.zip", b"this is not a zip")

    def test_zip_with_too_many_files_or_too_much_data_is_rejected(self):
        many = make_zip({f"f{i}.py": "x = 1\n" for i in range(ingest.MAX_FILES + 1)})
        with self.assertRaises(IngestError):
            read_upload("many.zip", many)
        chunk = "x = 1\n" * 70000  # about 420 KB each, below the per-file limit
        heavy = make_zip({f"f{i}.py": chunk for i in range(8)})
        with self.assertRaises(IngestError):
            read_upload("heavy.zip", heavy)

    def test_safe_filename(self):
        self.assertEqual(ingest.safe_filename("../../etc/passwd"), "snippet.py")
        self.assertEqual(ingest.safe_filename("my app.py"), "my_app.py")
        self.assertEqual(ingest.safe_filename(""), "snippet.py")
        self.assertEqual(ingest.safe_filename("main.js"), "main.js")

    def test_parse_github_url(self):
        self.assertEqual(ingest.parse_github_url("https://github.com/psf/requests"), ("psf", "requests", None))
        self.assertEqual(ingest.parse_github_url("github.com/psf/requests/"), ("psf", "requests", None))
        self.assertEqual(
            ingest.parse_github_url("https://github.com/psf/requests/tree/main"), ("psf", "requests", "main")
        )
        self.assertEqual(
            ingest.parse_github_url("https://github.com/psf/requests.git"), ("psf", "requests", None)
        )
        for bad in ("not a url", "https://example.com/psf/requests", "https://github.com/psf"):
            with self.assertRaises(IngestError):
                ingest.parse_github_url(bad)

    def test_fetch_github_repo_downloads_default_branch_zip(self):
        # No real network call: urlopen is mocked, but the URL it's asked to fetch,
        # the branch fallback order, and the resulting file list are all checked for real.
        zip_bytes = make_zip({"app.py": "x = 1\n"})
        requested_urls = []

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
            url = request.full_url
            requested_urls.append(url)
            if url.endswith("/refs/heads/main"):
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
            return FakeResponse(zip_bytes)

        with unittest.mock.patch("scanner.analyzer.ingest.urllib.request.urlopen", fake_urlopen):
            files = ingest.fetch_github_repo("https://github.com/someone/somerepo")

        self.assertEqual(files, [("app.py", "x = 1\n")])
        # "main" was tried and failed (404) before falling back to "master".
        self.assertEqual(
            requested_urls,
            [
                "https://codeload.github.com/someone/somerepo/zip/refs/heads/main",
                "https://codeload.github.com/someone/somerepo/zip/refs/heads/master",
            ],
        )

    def test_fetch_github_repo_reports_not_found(self):
        def fake_urlopen(request, timeout):
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", None, None)

        with unittest.mock.patch("scanner.analyzer.ingest.urllib.request.urlopen", fake_urlopen):
            with self.assertRaises(IngestError):
                ingest.fetch_github_repo("https://github.com/someone/private-repo")


if __name__ == "__main__":
    unittest.main()
