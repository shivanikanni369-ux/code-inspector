"""Runs every checker over a set of files and turns the findings into a score."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .common import file_extension
from .generic_checks import analyze_generic
from .python_checks import analyze_python
from .rules import HIGH, LOW, MEDIUM, RULES, SEVERITY_RANK, SEVERITY_WEIGHT, Issue

# One noisy rule must not zero the score, so each rule's penalty is capped by its severity.
PENALTY_CAP = {HIGH: 30, MEDIUM: 16, LOW: 5}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (50, "D")]


@dataclass
class ScanReport:
    issues: list[Issue]
    files_scanned: int
    score: int
    grade: str
    counts: dict = field(default_factory=dict)


def scan_source(path: str, source: str) -> list[Issue]:
    issues: list[Issue] = []
    if file_extension(path) == ".py":
        issues.extend(analyze_python(path, source))
    issues.extend(analyze_generic(path, source))
    return issues


def compute_score(issues: list[Issue]) -> int:
    penalty_by_rule: dict[str, int] = defaultdict(int)
    for issue in issues:
        penalty_by_rule[issue.rule_id] += SEVERITY_WEIGHT[issue.severity]
    total = sum(min(p, PENALTY_CAP[RULES[rule_id].severity]) for rule_id, p in penalty_by_rule.items())
    return max(0, 100 - total)


def grade_for(score: int) -> str:
    for minimum, letter in GRADES:
        if score >= minimum:
            return letter
    return "F"


def scan_files(files: list[tuple[str, str]]) -> ScanReport:
    seen: set = set()
    issues: list[Issue] = []
    for path, source in files:
        for issue in scan_source(path, source):
            key = (issue.rule_id, issue.file_path, issue.line, issue.detail)
            if key not in seen:
                seen.add(key)
                issues.append(issue)
    issues.sort(key=lambda i: (SEVERITY_RANK[i.severity], i.file_path, i.line))

    tally = Counter(i.severity for i in issues)
    counts = {HIGH: tally[HIGH], MEDIUM: tally[MEDIUM], LOW: tally[LOW]}
    score = compute_score(issues)
    return ScanReport(issues=issues, files_scanned=len(files), score=score, grade=grade_for(score), counts=counts)
