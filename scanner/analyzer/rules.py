"""Rule catalogue and the Issue record produced by the analyzer.

Nothing in this package imports Django, so the engine can be tested,
run from the command line, or reused in another project on its own.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
SECURITY, QUALITY = "security", "quality"

SEVERITY_RANK = {HIGH: 0, MEDIUM: 1, LOW: 2}
SEVERITY_WEIGHT = {HIGH: 10, MEDIUM: 4, LOW: 1}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    fix: str


RULES = {
    r.id: r
    for r in [
        # ------------------------------------------------------- security (Python)
        Rule("PY-EVAL", "Use of eval()/exec() on dynamic input", HIGH, SECURITY,
             "Avoid eval()/exec() on dynamic data. Use ast.literal_eval for literals, "
             "or map allowed inputs to functions explicitly."),
        Rule("PY-SHELL", "Possible shell command injection", HIGH, SECURITY,
             "Pass the command as a list of arguments with shell=False. If you must build "
             "a shell string, quote every value with shlex.quote()."),
        Rule("PY-SQLI", "SQL query built from strings (SQL injection risk)", HIGH, SECURITY,
             "Use parameterized queries, e.g. cursor.execute('SELECT ... WHERE id = %s', [user_id]), "
             "or the Django ORM. Never build SQL with f-strings, +, % or .format()."),
        Rule("PY-SECRET", "Hardcoded password, key or token", HIGH, SECURITY,
             "Load secrets from environment variables or a secrets manager. If this value was "
             "ever committed, treat it as leaked and rotate it."),
        Rule("PY-WEAK-HASH", "Weak hash algorithm (MD5/SHA-1)", MEDIUM, SECURITY,
             "Use hashlib.sha256 (or blake2) for integrity checks, and a password hasher such as "
             "Argon2, bcrypt or Django's make_password for passwords."),
        Rule("PY-DESERIALIZE", "Unsafe deserialization", MEDIUM, SECURITY,
             "Use JSON for untrusted data. For YAML use yaml.safe_load. Only unpickle data "
             "that you created and trust."),
        Rule("PY-TLS-OFF", "TLS certificate verification disabled", MEDIUM, SECURITY,
             "Remove verify=False. If you use a private CA, pass its bundle: verify='/path/to/ca.pem'."),
        Rule("PY-DEBUG", "Debug mode enabled", MEDIUM, SECURITY,
             "Read DEBUG from an environment variable and default it to False. "
             "Never run with debug mode on in production."),
        Rule("PY-HOSTS", "ALLOWED_HOSTS allows every host", MEDIUM, SECURITY,
             "List the exact domains you serve in ALLOWED_HOSTS instead of '*'."),
        Rule("PY-TEMPFILE", "Insecure temporary file (tempfile.mktemp)", MEDIUM, SECURITY,
             "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile(), which create the file safely."),
        Rule("PY-CHMOD", "World-writable file permissions", MEDIUM, SECURITY,
             "Avoid world-writable modes. Use 0o600 for private files or 0o755 for executables."),
        # ------------------------------------------------------- security (any file)
        Rule("SEC-SECRET", "Hardcoded password, key or token", HIGH, SECURITY,
             "Move the value to an environment variable or secrets manager and rotate it, "
             "since it is now in your source history."),
        Rule("SEC-AWS-KEY", "AWS access key ID found in source", HIGH, SECURITY,
             "Revoke this key immediately, create a new one, and load credentials from the "
             "environment or an IAM role."),
        Rule("SEC-PRIVATE-KEY", "Private key found in source", HIGH, SECURITY,
             "Remove the key from the code, revoke and replace it, and keep keys in a secrets manager."),
        Rule("SEC-ENV-FILE", "Environment file included in the upload", MEDIUM, SECURITY,
             "Add .env files to .gitignore and commit only a .env.example with placeholder values."),
        # ------------------------------------------------------- security (web files)
        Rule("WEB-EVAL", "Use of eval()", HIGH, SECURITY,
             "Avoid eval(). Parse data with JSON.parse (JavaScript) or use explicit logic."),
        Rule("WEB-INNERHTML", "Unsafe HTML injection (XSS risk)", MEDIUM, SECURITY,
             "Use textContent, or sanitize the HTML first (for example with DOMPurify)."),
        Rule("WEB-DOCWRITE", "document.write() call", MEDIUM, SECURITY,
             "Build DOM nodes with createElement/textContent instead of writing raw HTML."),
        Rule("WEB-TLS-OFF", "TLS certificate verification disabled", MEDIUM, SECURITY,
             "Do not disable certificate checks. Fix the certificate chain instead."),
        # ------------------------------------------------------- code quality
        Rule("Q-LONG-FUNC", "Function is too long", LOW, QUALITY,
             "Split the function into smaller functions that each do one thing."),
        Rule("Q-COMPLEX", "Function is too complex", LOW, QUALITY,
             "Reduce branching: use early returns, extract helpers, or replace long if/elif "
             "chains with a dictionary."),
        Rule("Q-MANY-ARGS", "Function takes too many arguments", LOW, QUALITY,
             "Group related arguments into a dataclass or object."),
        Rule("Q-UNUSED-IMPORT", "Unused import", LOW, QUALITY,
             "Remove the import to keep the file clean."),
        Rule("Q-BARE-EXCEPT", "Overly broad or silent exception handling", LOW, QUALITY,
             "Catch specific exception types and handle or log them instead of ignoring errors."),
        Rule("Q-MUTABLE-DEFAULT", "Mutable default argument", MEDIUM, QUALITY,
             "Use None as the default and create the list/dict inside the function."),
        Rule("Q-SYNTAX", "File could not be parsed", MEDIUM, QUALITY,
             "Fix the syntax error so the file can be analyzed. (Python 2 code also lands here.)"),
    ]
}


@dataclass
class Issue:
    rule_id: str
    title: str
    severity: str
    category: str
    file_path: str
    line: int
    snippet: str
    fix: str
    detail: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def make_issue(rule_id: str, file_path: str, line: int, snippet: str = "",
               detail: str = "", severity: str | None = None) -> Issue:
    rule = RULES[rule_id]
    return Issue(
        rule_id=rule.id,
        title=rule.title,
        severity=severity or rule.severity,
        category=rule.category,
        file_path=file_path,
        line=max(int(line or 1), 1),
        snippet=snippet.strip()[:200],
        fix=rule.fix,
        detail=detail[:300],
    )
