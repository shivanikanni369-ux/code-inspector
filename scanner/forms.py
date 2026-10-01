from django import forms
from django.core.exceptions import ValidationError

from .analyzer import ingest


class ScanForm(forms.Form):
    name = forms.CharField(max_length=200, required=False, label="Scan name (optional)")
    code = forms.CharField(
        required=False,
        strip=False,  # keep indentation exactly as pasted
        max_length=ingest.MAX_FILE_BYTES,
        label="Paste code",
        widget=forms.Textarea(attrs={"rows": 14, "spellcheck": "false",
                                     "placeholder": "Paste Python, JavaScript, PHP ... code here"}),
    )
    filename = forms.CharField(
        required=False, max_length=100, initial="snippet.py", label="File name for pasted code",
        help_text="The extension picks the checks that run, for example app.py or main.js.",
    )
    upload = forms.FileField(required=False, label="...or upload a source file or a ZIP")
    repo_url = forms.CharField(
        required=False,
        max_length=300,
        label="...or scan a public GitHub repo",
        widget=forms.TextInput(attrs={"placeholder": "https://github.com/owner/repo"}),
        help_text="Downloads the repo's default branch as a ZIP (add /tree/branch-name for a "
                   "specific branch). Public repositories only.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scanned_files = []
        self.upload_name = ""
        self.repo_name = ""

    def clean(self):
        cleaned = super().clean()
        code = cleaned.get("code") or ""
        upload = cleaned.get("upload")
        repo_url = (cleaned.get("repo_url") or "").strip()
        has_code = bool(code.strip())
        has_upload = upload is not None
        has_repo = bool(repo_url)
        if sum([has_code, has_upload, has_repo]) != 1:
            raise ValidationError(
                "Paste some code OR upload a file/ZIP OR give a GitHub repo URL (choose exactly one)."
            )

        try:
            if has_upload:
                if upload.size > ingest.MAX_UPLOAD_BYTES:
                    raise ingest.IngestError("That upload is larger than 5 MB.")
                self.upload_name = upload.name
                self.files = ingest.read_upload(upload.name, upload.read())
            elif has_repo:
                self.repo_name = repo_url.rstrip("/").rsplit("/", 1)[-1]
                self.files = ingest.fetch_github_repo(repo_url)
            else:
                self.files = [(ingest.safe_filename(cleaned.get("filename")), code)]
        except ingest.IngestError as exc:
            raise ValidationError(str(exc)) from exc

        if not self.files:
            raise ValidationError("No scannable source files were found in that upload.")
        return cleaned

    def scan_name(self):
        given = (self.cleaned_data.get("name") or "").strip()
        if given:
            return given
        if self.repo_name:
            return self.repo_name[:200]
        if self.upload_name:
            return self.upload_name[:200]
        return "Pasted snippet"
