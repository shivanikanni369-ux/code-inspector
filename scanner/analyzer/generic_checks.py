"""Line-based regex checks that work on any text file (secrets, JavaScript, PHP, config files)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .common import (
    SECRET_WORDS, file_extension, is_secret_name, looks_like_placeholder, mask_secrets,
    SECRET_NAME, MIN_SECRET_LENGTH,
)
from .rules import Issue, make_issue

MAX_LINE_LENGTH = 400  # keeps regex work bounded on minified files

WEB_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".php", ".html", ".htm"}
CONFIG_EXTENSIONS = {".env", ".yml", ".yaml", ".ini", ".cfg", ".properties"}

_NAME = r"([\w.-]{0,60}" + SECRET_WORDS + r"[\w.-]{0,60})"
QUOTED_SECRET = re.compile(_NAME + r"""["']?\s*[:=]\s*["']([^"'\s]{6,})["']""", re.IGNORECASE)
UNQUOTED_SECRET = re.compile(
    r"^\s*(?:export\s+)?" + _NAME + r"""\s*[:=]\s*([^\s#"'$<{%][^\s#]{5,})\s*$""", re.IGNORECASE
)


@dataclass(frozen=True)
class _LineRule:
    rule_id: str
    pattern: re.Pattern
    only: frozenset | None = None      # run only on these extensions
    exclude: frozenset = frozenset()   # never run on these extensions
    skip_comments: bool = False
    mask: bool = False
    secret_check: bool = False         # pattern has (name, value) groups


_LINE_RULES = [
    _LineRule("SEC-AWS-KEY", re.compile(r"AKIA[0-9A-Z]{16}"), mask=True),
    _LineRule(
        "SEC-PRIVATE-KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
    ),
    # Python files get the smarter AST-based secret check instead.
    _LineRule("SEC-SECRET", QUOTED_SECRET, exclude=frozenset({".py"}), skip_comments=True, mask=True, secret_check=True),
    _LineRule("SEC-SECRET", UNQUOTED_SECRET, only=frozenset(CONFIG_EXTENSIONS), skip_comments=True, mask=True, secret_check=True),
    _LineRule("WEB-EVAL", re.compile(r"(?<![\w.])eval\s*\("), only=frozenset({".js", ".jsx", ".ts", ".tsx", ".php"}), skip_comments=True),
    _LineRule("WEB-INNERHTML", re.compile(r"\.(?:inner|outer)HTML\s*\+?=|dangerouslySetInnerHTML"), only=frozenset({".js", ".jsx", ".ts", ".tsx"}), skip_comments=True),
    _LineRule("WEB-DOCWRITE", re.compile(r"document\.write(?:ln)?\s*\("), only=frozenset(WEB_EXTENSIONS), skip_comments=True),
    _LineRule("WEB-TLS-OFF", re.compile(r"rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)", re.IGNORECASE), only=frozenset({".js", ".ts", ".php"}), skip_comments=True),
]


def _looks_like_value(name: str, value: str) -> bool:
    if not is_secret_name(name) or looks_like_placeholder(value):
        return False
    if len(value) < MIN_SECRET_LENGTH or value.startswith(("http://", "https://", "/", "./")):
        return False
    return True


def analyze_generic(path: str, source: str) -> list[Issue]:
    ext = file_extension(path)
    base = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    issues: list[Issue] = []

    if ext == ".env" and not base.endswith((".example", ".sample", ".template")):
        issues.append(make_issue("SEC-ENV-FILE", path, 1, base))

    for lineno, raw in enumerate(source.splitlines(), start=1):
        line = raw[:MAX_LINE_LENGTH]
        stripped = line.strip()
        if not stripped:
            continue
        is_comment = stripped.startswith(("#", "//", "/*", "*"))
        has_secret_word = bool(SECRET_NAME.search(line))

        for rule in _LINE_RULES:
            if rule.only is not None and ext not in rule.only:
                continue
            if ext in rule.exclude or (rule.skip_comments and is_comment):
                continue
            if rule.secret_check and not has_secret_word:
                continue
            match = rule.pattern.search(line)
            if not match:
                continue
            if rule.secret_check and not _looks_like_value(match.group(1), match.group(2)):
                continue
            snippet = mask_secrets(line) if rule.mask else line
            issues.append(make_issue(rule.rule_id, path, lineno, snippet))
    return issues
