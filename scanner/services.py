"""Scan creation shared by the web pages and the REST API."""
from django.db import transaction

from .analyzer import scan_files
from .analyzer.rules import SEVERITY_RANK
from .models import Issue, Scan

MAX_ISSUES_STORED = 2000  # keeps one huge scan from filling the database


def create_scan(owner, name, files):
    """Analyze (read-only, nothing is executed) and save the scan with its findings."""
    report = scan_files(files)
    stored = report.issues[:MAX_ISSUES_STORED]
    with transaction.atomic():
        scan = Scan.objects.create(
            owner=owner,
            name=name,
            files_scanned=report.files_scanned,
            score=report.score,
            grade=report.grade,
            high_count=report.counts["HIGH"],
            medium_count=report.counts["MEDIUM"],
            low_count=report.counts["LOW"],
            issues_truncated=len(report.issues) > MAX_ISSUES_STORED,
        )
        Issue.objects.bulk_create(
            [
                Issue(
                    scan=scan,
                    rank=SEVERITY_RANK[i.severity],
                    rule_id=i.rule_id,
                    title=i.title,
                    severity=i.severity,
                    category=i.category,
                    file_path=i.file_path[:500],
                    line=i.line,
                    snippet=i.snippet,
                    detail=i.detail,
                    fix=i.fix,
                )
                for i in stored
            ]
        )
    return scan
