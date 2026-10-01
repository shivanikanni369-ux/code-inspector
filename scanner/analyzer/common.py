"""Small helpers shared by the Python and generic checkers."""
from __future__ import annotations

import re
from pathlib import PurePosixPath

# Words that make a variable / key name look like it holds a credential.
SECRET_WORDS = (
    r"(?:passw(?:or)?d|(?<![a-z])pass(?![a-z])|secret|api[_-]?key|access[_-]?key|"
    r"auth[_-]?token|token(?!iz)|private[_-]?key|credential)"
)
SECRET_NAME = re.compile(SECRET_WORDS, re.IGNORECASE)

# Names such as PASSWORD_FIELD, token_url or secretName describe a secret, they do not hold one.
SAFE_NAME_ENDINGS = (
    "url", "uri", "path", "name", "label", "field", "type", "header", "message", "msg",
    "error", "text", "env", "regex", "pattern", "help", "prompt", "hint", "id", "words",
)

_PLACEHOLDER_PREFIXES = ("<", "${", "{{", "%(", "your", "example", "dummy", "placeholder", "todo")
MIN_SECRET_LENGTH = 6


def file_extension(path: str) -> str:
    """Lower-case extension; every .env / .env.local style file counts as '.env'."""
    base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base.startswith(".env"):
        return ".env"
    return PurePosixPath(base).suffix


def is_secret_name(name: str) -> bool:
    lowered = name.lower()
    if lowered.endswith(SAFE_NAME_ENDINGS):
        return False
    return bool(SECRET_NAME.search(name))


def looks_like_placeholder(value: str) -> bool:
    v = value.strip().lower()
    if v.startswith(_PLACEHOLDER_PREFIXES):
        return True
    return bool(v) and set(v) <= set("x*-._")


def is_hardcoded_secret_value(value: str) -> bool:
    if len(value) < MIN_SECRET_LENGTH or any(ch.isspace() for ch in value):
        return False
    return not looks_like_placeholder(value)


_QUOTED = re.compile(r"""(['"])([^'"\n]{4,})\1""")
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_UNQUOTED_VALUE = re.compile(r"([=:])\s*([^\s'\"#]{6,})\s*$")


def mask_secrets(line: str) -> str:
    """Hide secret values so the report never repeats a leaked credential in full."""
    line = _AWS_KEY.sub("AKIA****************", line)
    line = _QUOTED.sub(lambda m: f"{m.group(1)}****{m.group(1)}", line)
    return _UNQUOTED_VALUE.sub(lambda m: f"{m.group(1)} ****", line)


def is_test_path(path: str) -> bool:
    """Test files often contain fake credentials on purpose, so they are reported at low severity."""
    norm = path.replace("\\", "/").lower()
    base = norm.rsplit("/", 1)[-1]
    parts = norm.split("/")[:-1]
    return (
        any(p in ("test", "tests", "__tests__", "spec") for p in parts)
        or base.startswith("test_")
        or base.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
        or base == "conftest.py"
    )
