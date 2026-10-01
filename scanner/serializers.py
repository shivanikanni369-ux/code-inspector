from rest_framework import serializers

from .analyzer import ingest
from .models import Issue, Scan


class IssueSerializer(serializers.ModelSerializer):
    class Meta:
        model = Issue
        fields = ["rule_id", "title", "severity", "category", "file_path", "line", "snippet", "detail", "fix"]


class ScanSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = [
            "id", "name", "created_at", "files_scanned", "score", "grade",
            "high_count", "medium_count", "low_count", "total_issues",
        ]


class ScanDetailSerializer(ScanSummarySerializer):
    issues = IssueSerializer(many=True, read_only=True)

    class Meta(ScanSummarySerializer.Meta):
        fields = ScanSummarySerializer.Meta.fields + ["issues_truncated", "issues"]


class ScanCreateSerializer(serializers.Serializer):
    """Send `code` (plus an optional `filename`), a multipart `upload` (file or ZIP),
    or `repo_url` pointing at a public GitHub repository."""

    name = serializers.CharField(max_length=200, required=False, allow_blank=True)
    filename = serializers.CharField(max_length=100, required=False, allow_blank=True)
    code = serializers.CharField(
        required=False, allow_blank=True, trim_whitespace=False, max_length=ingest.MAX_FILE_BYTES
    )
    upload = serializers.FileField(required=False, write_only=True)
    repo_url = serializers.CharField(max_length=300, required=False, allow_blank=True)

    def validate(self, attrs):
        code = attrs.get("code") or ""
        upload = attrs.get("upload")
        repo_url = (attrs.get("repo_url") or "").strip()
        has_code = bool(code.strip())
        has_upload = upload is not None
        has_repo = bool(repo_url)
        if sum([has_code, has_upload, has_repo]) != 1:
            raise serializers.ValidationError("Send exactly one of 'code', 'upload' or 'repo_url'.")

        try:
            if has_upload:
                if upload.size > ingest.MAX_UPLOAD_BYTES:
                    raise ingest.IngestError("That upload is larger than 5 MB.")
                files = ingest.read_upload(upload.name, upload.read())
                upload_name = upload.name
            elif has_repo:
                files = ingest.fetch_github_repo(repo_url)
                upload_name = repo_url.rstrip("/").rsplit("/", 1)[-1]
            else:
                files = [(ingest.safe_filename(attrs.get("filename")), code)]
                upload_name = ""
        except ingest.IngestError as exc:
            raise serializers.ValidationError(str(exc)) from exc

        if not files:
            raise serializers.ValidationError("No scannable source files were found.")
        attrs["files"] = files
        attrs["scan_name"] = (attrs.get("name") or "").strip() or upload_name[:200] or "API scan"
        return attrs
