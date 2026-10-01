"""Static checks for Python files.

The code is only *parsed* with ast.parse() and walked as a syntax tree.
It is never imported, compiled or executed.
"""
from __future__ import annotations

import ast
import re

from .common import is_hardcoded_secret_value, is_secret_name, is_test_path, mask_secrets
from .rules import LOW, MEDIUM, Issue, make_issue

SUBPROCESS_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput",
}
SHELL_FUNCS = {"os.system", "os.popen"}
SQL_METHODS = {"execute", "executemany", "executescript", "raw"}
WEAK_HASHES = {"hashlib.md5", "hashlib.sha1"}
UNSAFE_LOADERS = {
    "pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads",
    "marshal.load", "marshal.loads", "dill.load", "dill.loads",
}
SQL_WORDS = re.compile(
    r"\b(select|insert|update|delete|drop|alter|create|where|from|values|union)\b", re.IGNORECASE
)

MAX_FUNCTION_LINES = 50
MAX_ARGS = 7
COMPLEXITY_WARN = 10
COMPLEXITY_HIGH = 15


# --------------------------------------------------------------------- helpers
def _dotted(node: ast.AST) -> str:
    """'subprocess.run' for attribute chains, 'eval' for a bare name, '' otherwise."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _collect_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local names to what they import, so `import subprocess as sp` still matches."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _is_dynamic_sql(arg: ast.AST) -> bool:
    """True when a SQL-looking string is assembled from variables instead of parameters."""
    if isinstance(arg, ast.JoinedStr):  # f"SELECT ... {x}"
        literal = "".join(
            p.value for p in arg.values if isinstance(p, ast.Constant) and isinstance(p.value, str)
        )
        has_placeholder = any(isinstance(p, ast.FormattedValue) for p in arg.values)
        return has_placeholder and bool(SQL_WORDS.search(literal))
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):  # "..." + x  /  "..." % x
        nodes = list(ast.walk(arg))
        literal = " ".join(
            n.value for n in nodes if isinstance(n, ast.Constant) and isinstance(n.value, str)
        )
        has_variable = any(
            isinstance(n, (ast.Name, ast.Attribute, ast.Call, ast.Subscript, ast.JoinedStr)) for n in nodes
        )
        return has_variable and bool(SQL_WORDS.search(literal))
    if (  # "SELECT ... {}".format(x)
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Attribute)
        and arg.func.attr == "format"
        and isinstance(arg.func.value, ast.Constant)
        and isinstance(arg.func.value.value, str)
    ):
        return bool(SQL_WORDS.search(arg.func.value.value)) and bool(arg.args or arg.keywords)
    return False


def _yaml_uses_safe_loader(call: ast.Call) -> bool:
    loader = None
    for kw in call.keywords:
        if kw.arg == "Loader":
            loader = kw.value
    if loader is None and len(call.args) > 1:
        loader = call.args[1]
    return loader is not None and _dotted(loader).endswith(("SafeLoader", "CSafeLoader"))


def _complexity(func: ast.AST) -> int:
    """McCabe cyclomatic complexity: 1 + branches (nested functions are counted on their own)."""
    score = 1
    stack = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler)):
            score += 1
        elif isinstance(node, ast.comprehension):
            score += 1 + len(node.ifs)
        elif isinstance(node, ast.match_case):
            score += 1
        stack.extend(ast.iter_child_nodes(node))
    return score


def _is_mutable_default(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    return isinstance(node, ast.Call) and _dotted(node.func) in ("list", "dict", "set")


# --------------------------------------------------------------------- checker
class _PythonChecker(ast.NodeVisitor):
    def __init__(self, path: str, source: str, tree: ast.AST):
        self.path = path
        self.tree = tree
        self.lines = source.splitlines()
        self.aliases = _collect_aliases(tree)
        self.is_test_file = is_test_path(path)
        self.issues: list[Issue] = []

    # -- utilities
    def add(self, rule_id: str, node: ast.AST, detail: str = "",
            severity: str | None = None, mask: bool = False) -> None:
        line = getattr(node, "lineno", 1)
        text = self.lines[line - 1] if 1 <= line <= len(self.lines) else ""
        if mask:
            text = mask_secrets(text)
        self.issues.append(make_issue(rule_id, self.path, line, text, detail, severity))

    def resolve(self, node: ast.AST) -> str:
        name = _dotted(node)
        if not name:
            return ""
        first, _, rest = name.partition(".")
        target = self.aliases.get(first)
        if target:
            return f"{target}.{rest}" if rest else target
        return name

    def check_secret(self, name: str, value: ast.AST, at: ast.AST) -> None:
        if (
            isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and is_secret_name(name)
            and is_hardcoded_secret_value(value.value)
            and value.value.lower() != name.lower()
        ):
            detail = f"'{name}' is set to a literal string"
            if self.is_test_file:
                self.add("PY-SECRET", at, detail + " (test file, so reported as low)", severity=LOW, mask=True)
            else:
                self.add("PY-SECRET", at, detail, mask=True)

    # -- calls
    def visit_Call(self, node: ast.Call) -> None:
        name = self.resolve(node.func)
        first_arg = node.args[0] if node.args else None
        dynamic = first_arg is not None and not isinstance(first_arg, ast.Constant)

        self._check_code_execution(node, name, dynamic)
        self._check_sql(node, first_arg)
        self._check_crypto_and_loading(node, name, first_arg)
        self._check_misconfiguration(node, name)

        for kw in node.keywords:
            if kw.arg:
                self.check_secret(kw.arg, kw.value, kw.value)
        self.generic_visit(node)

    def _check_code_execution(self, node: ast.Call, name: str, dynamic: bool) -> None:
        if name in ("eval", "exec") and dynamic:
            self.add("PY-EVAL", node, f"{name}() is called with a non-constant argument")
        if name in SUBPROCESS_FUNCS and any(kw.arg == "shell" and _is_true(kw.value) for kw in node.keywords):
            self.add("PY-SHELL", node, "shell=True", severity=None if dynamic else MEDIUM)
        if name in SHELL_FUNCS and dynamic:
            self.add("PY-SHELL", node, f"{name}() runs a non-constant command")

    def _check_sql(self, node: ast.Call, first_arg: ast.AST | None) -> None:
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in SQL_METHODS
            and first_arg is not None
            and _is_dynamic_sql(first_arg)
        ):
            self.add("PY-SQLI", node, f".{node.func.attr}() receives a string built from variables")

    def _check_crypto_and_loading(self, node: ast.Call, name: str, first_arg: ast.AST | None) -> None:
        uses_for_security = not any(kw.arg == "usedforsecurity" and _is_false(kw.value) for kw in node.keywords)
        weak_by_name = name in WEAK_HASHES
        weak_by_argument = (
            name == "hashlib.new"
            and isinstance(first_arg, ast.Constant)
            and str(first_arg.value).lower() in ("md5", "sha1")
        )
        if uses_for_security and (weak_by_name or weak_by_argument):
            self.add("PY-WEAK-HASH", node, name)

        if name in UNSAFE_LOADERS:
            self.add("PY-DESERIALIZE", node, f"{name}() can run code when given untrusted data")
        elif name == "yaml.load" and not _yaml_uses_safe_loader(node):
            self.add("PY-DESERIALIZE", node, "yaml.load() without SafeLoader")

    def _check_misconfiguration(self, node: ast.Call, name: str) -> None:
        if any(kw.arg == "verify" and _is_false(kw.value) for kw in node.keywords):
            self.add("PY-TLS-OFF", node, "verify=False")

        is_run_call = isinstance(node.func, ast.Attribute) and node.func.attr == "run"
        if is_run_call and any(kw.arg == "debug" and _is_true(kw.value) for kw in node.keywords):
            self.add("PY-DEBUG", node, "run(debug=True)")

        if name == "tempfile.mktemp":
            self.add("PY-TEMPFILE", node)

        if name == "os.chmod" and len(node.args) >= 2:
            mode = node.args[1]
            if isinstance(mode, ast.Constant) and isinstance(mode.value, int) and mode.value & 0o002:
                self.add("PY-CHMOD", node, f"mode {oct(mode.value)}")

    # -- assignments and dict literals
    def _check_assignment(self, target: ast.AST, value: ast.AST, at: ast.AST) -> None:
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Attribute):
            name = target.attr
        else:
            return
        upper = name.upper()
        if upper == "DEBUG" and _is_true(value):
            self.add("PY-DEBUG", at, "DEBUG is set to True")
        if (
            upper == "ALLOWED_HOSTS"
            and isinstance(value, (ast.List, ast.Tuple, ast.Set))
            and any(isinstance(e, ast.Constant) and e.value == "*" for e in value.elts)
        ):
            self.add("PY-HOSTS", at, "ALLOWED_HOSTS contains '*'")
        self.check_secret(name, value, at)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_assignment(target, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_assignment(node.target, node.value, node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                self.check_secret(key.value, value, key)
        self.generic_visit(node)

    # -- exception handling
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        bare = node.type is None
        broad = bare or _dotted(node.type) in ("Exception", "BaseException")
        swallowed = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
        if bare or (broad and swallowed):
            parts = []
            if bare:
                parts.append("bare 'except:' also catches KeyboardInterrupt and SystemExit")
            if swallowed:
                parts.append("the error is silently ignored")
            self.add("Q-BARE-EXCEPT", node, "; ".join(parts))
        self.generic_visit(node)

    # -- functions
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        length = (node.end_lineno or node.lineno) - node.lineno + 1
        if length > MAX_FUNCTION_LINES:
            self.add("Q-LONG-FUNC", node, f"'{node.name}' is {length} lines long (limit {MAX_FUNCTION_LINES})")

        args = node.args
        count = len(args.posonlyargs) + len(args.args) + len(args.kwonlyargs)
        first = (args.posonlyargs + args.args)[:1]
        if first and first[0].arg in ("self", "cls"):
            count -= 1
        if count > MAX_ARGS:
            self.add("Q-MANY-ARGS", node, f"'{node.name}' takes {count} arguments (limit {MAX_ARGS})")

        score = _complexity(node)
        if score > COMPLEXITY_WARN:
            severity = MEDIUM if score > COMPLEXITY_HIGH else None
            self.add("Q-COMPLEX", node, f"'{node.name}' has complexity {score} (limit {COMPLEXITY_WARN})", severity)

        for default in list(args.defaults) + [d for d in args.kw_defaults if d is not None]:
            if _is_mutable_default(default):
                self.add("Q-MUTABLE-DEFAULT", default, f"'{node.name}' uses a mutable default value")
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    # -- imports (run after the walk)
    def _names_in_use(self) -> set[str]:
        used = {n.id for n in ast.walk(self.tree) if isinstance(n, ast.Name)}
        for node in ast.walk(self.tree):
            is_all = isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets
            )
            if is_all and isinstance(node.value, (ast.List, ast.Tuple)):
                used |= {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
        return used

    @staticmethod
    def _import_bindings(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Import):
            return [a.asname or a.name.split(".")[0] for a in node.names]
        if isinstance(node, ast.ImportFrom) and node.module != "__future__":
            return [a.asname or a.name for a in node.names if a.name != "*"]
        return []

    def check_unused_imports(self) -> None:
        if self.path.replace("\\", "/").rsplit("/", 1)[-1] == "__init__.py":
            return  # re-exporting names is normal in __init__.py
        used = self._names_in_use()
        for node in ast.walk(self.tree):
            for binding in self._import_bindings(node):
                if binding not in used:
                    self.add("Q-UNUSED-IMPORT", node, f"'{binding}' is imported but never used")


def analyze_python(path: str, source: str) -> list[Issue]:
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError, RecursionError) as exc:
        line = getattr(exc, "lineno", None) or 1
        reason = getattr(exc, "msg", None) or exc.__class__.__name__
        return [make_issue("Q-SYNTAX", path, line, detail=f"Could not parse file: {reason}")]
    checker = _PythonChecker(path, source, tree)
    checker.visit(tree)
    checker.check_unused_imports()
    return checker.issues
