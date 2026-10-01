"""Command-line use:  python -m scanner.analyzer <file | folder | .zip | github-url>"""
import os
import sys

from . import ingest
from .engine import scan_files


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m scanner.analyzer <file | folder | .zip | https://github.com/owner/repo>")
        return 2
    target = argv[1]
    try:
        if target.startswith(("http://", "https://")) or target.startswith("github.com/"):
            files = ingest.fetch_github_repo(target)
        elif os.path.isdir(target):
            files = ingest.read_directory(target)
        else:
            with open(target, "rb") as handle:
                files = ingest.read_upload(os.path.basename(target), handle.read())
    except (OSError, ingest.IngestError) as exc:
        print(f"error: {exc}")
        return 2

    report = scan_files(files)
    print(f"Scanned {report.files_scanned} file(s)  |  score {report.score}/100  |  grade {report.grade}")
    print(f"HIGH {report.counts['HIGH']}   MEDIUM {report.counts['MEDIUM']}   LOW {report.counts['LOW']}\n")
    for issue in report.issues:
        print(f"[{issue.severity:<6}] {issue.file_path}:{issue.line}  {issue.rule_id}  {issue.title}")
        if issue.detail:
            print(f"           {issue.detail}")
    return 1 if report.counts["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
