"""Safe reading of pasted files, ZIP archives and folders.

Security rules for this module:
  * Uploaded code is NEVER executed, imported or compiled. It is only read as text.
  * ZIP files are read in memory. Nothing is extracted to disk, so path-traversal
    entries ("../../x") cannot write anywhere.
  * Hard limits on file count, file size and total size protect against ZIP bombs.
"""
from __future__ import annotations

import io
import os
import re
import urllib.error
import urllib.request
import zipfile
import zlib
from pathlib import PurePosixPath

from .common import file_extension

MAX_UPLOAD_BYTES = 5 * 1024 * 1024      # size of the uploaded file itself
MAX_FILE_BYTES = 500 * 1024             # one source file
MAX_TOTAL_BYTES = 3 * 1024 * 1024       # all source files together
MAX_FILES = 300
MAX_ZIP_ENTRIES = 5000
GITHUB_FETCH_TIMEOUT = 15               # seconds

ALLOWED_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java", ".rb", ".go",
    ".html", ".htm", ".yml", ".yaml", ".json", ".ini", ".cfg", ".properties", ".sh", ".env",
}
IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "env", "__pycache__", "site-packages",
    "dist", "build", ".idea", ".vscode", ".mypy_cache", ".pytest_cache",
}


class IngestError(ValueError):
    """The upload cannot be scanned (message is safe to show to the user)."""


def safe_filename(name: str | None, default: str = "snippet.py") -> str:
    base = PurePosixPath((name or "").replace("\\", "/")).name
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:100]
    if not base or not is_scannable(base):
        return default
    return base


def is_scannable(path: str) -> bool:
    return file_extension(path) in ALLOWED_SUFFIXES


def _clean_path(raw: str) -> str | None:
    parts = [p for p in raw.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    if any(p in IGNORED_DIRS for p in parts[:-1]):
        return None
    return "/".join(parts)


def _decode(data: bytes) -> str | None:
    if b"\x00" in data[:8192]:
        return None  # binary file
    return data.decode("utf-8", errors="replace")


def read_upload(filename: str, data: bytes) -> list[tuple[str, str]]:
    """Return [(path, text)] for an uploaded single file or ZIP."""
    name = PurePosixPath((filename or "").replace("\\", "/")).name
    if not name:
        raise IngestError("The uploaded file has no name.")
    if name.lower().endswith(".zip"):
        return _read_zip(data)
    if not is_scannable(name):
        allowed = ", ".join(sorted(ALLOWED_SUFFIXES))
        raise IngestError(f"Unsupported file type. Upload a .zip or one of: {allowed}")
    if len(data) > MAX_FILE_BYTES:
        raise IngestError("That file is larger than 500 KB. Upload a ZIP of your source files instead.")
    text = _decode(data)
    if text is None:
        raise IngestError("That looks like a binary file, not source code.")
    return [(name, text)]


# GitHub owner/repo names only ever contain these characters, so this also doubles
# as a whitelist that keeps the URL we build below fully server-controlled.
_GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/"
    r"(?P<repo>[A-Za-z0-9._-]+?)"
    r"(?:\.git)?"
    r"(?:/(?:tree|blob)/(?P<branch>[A-Za-z0-9._/-]+))?"
    r"/?$"
)


def parse_github_url(url: str) -> tuple[str, str, str | None]:
    match = _GITHUB_URL_RE.match((url or "").strip())
    if not match:
        raise IngestError(
            "That doesn't look like a GitHub repository URL, e.g. https://github.com/owner/repo "
            "(optionally .../tree/branch-name)."
        )
    return match.group("owner"), match.group("repo"), match.group("branch")


def fetch_github_repo(url: str) -> list[tuple[str, str]]:
    """Download a public GitHub repo (default branch, or the one in the URL) and read it.

    Only codeload.github.com is ever contacted, over HTTPS, with a short timeout and the
    same size cap as any other upload. The repo is never cloned or executed -- its ZIP is
    downloaded and handed to the exact same reader used for uploaded ZIPs.
    """
    owner, repo, branch = parse_github_url(url)
    candidates = [branch] if branch else ["main", "master"]
    last_error: IngestError | None = None
    for candidate in candidates:
        codeload_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{candidate}"
        try:
            data = _download(codeload_url)
        except IngestError as exc:
            last_error = exc
            continue
        return read_upload(f"{repo}-{candidate}.zip", data)
    raise last_error or IngestError("Could not download that repository.")


def _download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "code-inspector-scanner"})
    try:
        with urllib.request.urlopen(request, timeout=GITHUB_FETCH_TIMEOUT) as response:
            data = response.read(MAX_UPLOAD_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise IngestError(
                "Repository or branch not found. It may be private, misspelled, "
                "or use a different default branch (try adding /tree/<branch>)."
            ) from exc
        raise IngestError(f"GitHub returned an error (HTTP {exc.code}).") from exc
    except urllib.error.URLError as exc:
        raise IngestError(f"Could not reach GitHub: {exc.reason}") from exc
    except TimeoutError as exc:
        raise IngestError("Timed out downloading that repository.") from exc
    if len(data) > MAX_UPLOAD_BYTES:
        raise IngestError("That repository's ZIP is larger than 5 MB.")
    return data


def _read_zip(data: bytes) -> list[tuple[str, str]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestError("That does not look like a valid ZIP file.") from exc

    files: list[tuple[str, str]] = []
    total = 0
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise IngestError("The ZIP contains too many entries.")

        candidates = []
        for info in infos:
            if info.is_dir():
                continue
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue  # symlink entry
            path = _clean_path(info.filename)
            if path is None or not is_scannable(path) or info.file_size > MAX_FILE_BYTES:
                continue
            candidates.append((path, info))
        if len(candidates) > MAX_FILES:
            raise IngestError(f"The ZIP has more than {MAX_FILES} source files. Upload a smaller project.")

        for path, info in candidates:
            try:
                with archive.open(info) as handle:
                    raw = handle.read(MAX_FILE_BYTES + 1)  # bounded read, headers can lie
            except (RuntimeError, NotImplementedError, EOFError, OSError, zipfile.BadZipFile, zlib.error) as exc:
                raise IngestError("The ZIP is encrypted, damaged or uses an unsupported format.") from exc
            if len(raw) > MAX_FILE_BYTES:
                continue
            total += len(raw)
            if total > MAX_TOTAL_BYTES:
                raise IngestError("The source files in the ZIP add up to more than 3 MB.")
            text = _decode(raw)
            if text is not None:
                files.append((path, text))
    return files


def read_directory(root: str) -> list[tuple[str, str]]:
    """Used by the command-line tool. Same filters as ZIP uploads, symlinks are skipped."""
    files: list[tuple[str, str]] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full) or not is_scannable(rel):
                continue
            try:
                with open(full, "rb") as handle:
                    raw = handle.read(MAX_FILE_BYTES + 1)
            except OSError:
                continue
            if len(raw) > MAX_FILE_BYTES:
                continue
            total += len(raw)
            if total > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
                raise IngestError("Folder is too large to scan (limit 300 files / 3 MB).")
            text = _decode(raw)
            if text is not None:
                files.append((rel, text))
    return files
