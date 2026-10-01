# Code Inspector & Security Analyzer

A Django web app that scans source code for **security vulnerabilities** and **code-quality problems**.
Users sign up, paste code, upload a file / ZIP, or point at a public GitHub repo, and get a graded
report (0-100 score, A-F grade) with severity levels, the exact file and line, and a suggested fix,
downloadable as JSON or PDF. Scan history is saved per user.

## What it detects

| Area | Examples |
|---|---|
| Security (Python, via AST) | `eval`/`exec` on dynamic input, `shell=True`, SQL built with f-strings / `+` / `%` / `.format()`, hardcoded passwords/keys/tokens, MD5/SHA-1, `pickle`/unsafe `yaml.load`, `verify=False`, `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, `tempfile.mktemp`, world-writable `chmod` |
| Security (any file) | AWS access keys, private keys, secrets in `.env`/YAML/JS files, committed `.env` files, `eval`, `innerHTML`, `document.write`, disabled TLS checks in JS/PHP |
| Quality (Python) | long functions, high cyclomatic complexity, too many arguments, unused imports, bare/silent `except`, mutable default arguments, syntax errors |

Secret values are **masked** in reports (`password = "****"`).

## Run it locally

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python manage.py makemigrations scanner
python manage.py migrate
python manage.py runserver        # open http://127.0.0.1:8000
```

Sign up, click **New scan**, and try `samples/vulnerable_example.py` (a deliberately insecure file
with fake credentials) to see a full report.

## Run the tests

```bash
python manage.py test                        # everything
python -m unittest scanner.tests.test_analyzer   # analyzer only, no Django needed
```

## Use the engine from the command line (no web server)

```bash
python -m scanner.analyzer samples/vulnerable_example.py
python -m scanner.analyzer path/to/project_folder_or_zip
python -m scanner.analyzer https://github.com/owner/repo
```

## REST API

Built with Django REST Framework. Requests are limited to 60 per minute per user, and you can only
ever see your own scans.

**Authentication** — two options:

- **Token (recommended).** Grab a token from the **API token** page after logging in on the website,
  or fetch one with `POST /api/token/` (`{"username": "...", "password": "..."}`). Send it as
  `Authorization: Token <key>`. Regenerating the token on the website invalidates the old one.
- **Basic auth.** Your website username and password on every request (use HTTPS in production).
  Handy for a quick curl/Postman check.

| Method | URL | What it does |
|---|---|---|
| POST | `/api/token/` | Exchange username + password for an API token |
| POST | `/api/scans/` | Run a scan. JSON body `{"filename": "app.py", "code": "...", "name": "optional"}`, a multipart `upload` (file or ZIP), or `{"repo_url": "https://github.com/owner/repo"}`. Returns `201` with the full report |
| GET | `/api/scans/` | List your scans (paginated, 20 per page) |
| GET | `/api/scans/<id>/` | One scan with all findings |
| GET | `/api/scans/<id>/report.pdf` | The same report as a downloadable PDF |
| DELETE | `/api/scans/<id>/` | Delete a scan (`204`) |
| GET | `/api/rules/` | The checks the analyzer runs |

```bash
# get a token
curl -X POST http://127.0.0.1:8000/api/token/ -d "username=alice&password=YOUR_PASSWORD"

# scan a snippet (token auth)
curl -H "Authorization: Token YOUR_TOKEN" -X POST http://127.0.0.1:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -d '{"filename": "app.py", "code": "import hashlib\nprint(hashlib.md5(b\"x\"))"}'

# scan a whole project
curl -H "Authorization: Token YOUR_TOKEN" -X POST http://127.0.0.1:8000/api/scans/ -F "upload=@project.zip"

# scan a public GitHub repo
curl -H "Authorization: Token YOUR_TOKEN" -X POST http://127.0.0.1:8000/api/scans/ \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/owner/repo"}'

# list scans
curl -H "Authorization: Token YOUR_TOKEN" http://127.0.0.1:8000/api/scans/

# download the PDF report for a scan
curl -H "Authorization: Token YOUR_TOKEN" http://127.0.0.1:8000/api/scans/1/report.pdf -o report.pdf

# or with basic auth instead of a token
curl -u alice:YOUR_PASSWORD http://127.0.0.1:8000/api/scans/
```

In Postman use Authorization > Bearer/API Key (header `Authorization: Token <key>`) or Basic Auth.
With debug on, opening `/api/scans/` in the browser after logging in shows DRF's browsable API.

## How it is built

```
config/            Django settings, URLs, WSGI
scanner/
  analyzer/        Framework-independent engine (no Django imports)
    rules.py         rule catalogue: id, title, severity, fix advice
    python_checks.py AST-based checks for Python
    generic_checks.py regex checks for secrets, JS, PHP, config files
    ingest.py        safe reading of files, ZIPs, folders and public GitHub repos
    engine.py        runs the checks, removes duplicates, computes the score
  models.py        Scan and Issue tables
  views.py         website pages: dashboard, new scan, report, JSON/PDF download, delete
  services.py      create_scan(): shared by the website and the API
  pdf_report.py    renders a Scan as a PDF (used by the website and the API)
  serializers.py, api_views.py, api_urls.py   REST API (Django REST Framework)
  templates/       HTML pages
  tests/           unit tests (engine) and view tests (web layer)
samples/           demo file for trying the tool
```

## Security design (the tool's own safety)

- Uploaded code is only **parsed as text**. It is never imported, compiled or executed.
- ZIPs are read in memory. Nothing is extracted to disk, so path-traversal entries do nothing.
- Limits: 500 KB per file, 3 MB and 300 files per ZIP, 5 MB per upload (including GitHub downloads).
- GitHub repo scanning only ever contacts `codeload.github.com`, over HTTPS, with a 15s timeout;
  the repo owner/name are validated against GitHub's own character rules before the URL is built,
  so a submitted `repo_url` can never redirect the request elsewhere. Only public repos work.
- Each user can only see and delete their own scans.
- Settings read secrets from environment variables. Production mode refuses to start without `DJANGO_SECRET_KEY`.
- How the score works: HIGH = -10, MEDIUM = -4, LOW = -1 per finding, and each rule's total penalty is capped
  so one noisy rule cannot zero the score. Grades: A 90+, B 80+, C 70+, D 50+, F below.

## Deploy (example: Render.com)

1. Push this folder to GitHub.
2. New **Web Service**, build command:
   `pip install -r requirements.txt && python manage.py collectstatic --noinput && python manage.py migrate`
3. Start command: `gunicorn config.wsgi`
4. Environment variables: `DJANGO_SECRET_KEY` (a long random string). `DJANGO_DEBUG` stays unset (off).
   Render's hostname is added to `ALLOWED_HOSTS` automatically.
5. Free-tier disks are temporary, so SQLite data resets on redeploy. Use PostgreSQL for permanent data.

## Known limits and ideas for next steps

- Pattern-based checks give hints, not proof: expect some false positives and misses.
- Only Python has deep (AST) analysis; other languages get regex checks.
- Ideas: run scans in a background worker, add Bandit/Radon as extra engines.
