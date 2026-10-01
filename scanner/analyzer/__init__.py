"""Framework-independent code analysis engine (no Django imports)."""
from .engine import ScanReport, compute_score, scan_files, scan_source
from .ingest import IngestError, read_upload

__all__ = ["IngestError", "ScanReport", "compute_score", "read_upload", "scan_files", "scan_source"]
