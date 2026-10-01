from django.conf import settings
from django.db import models


class Scan(models.Model):
    """One run of the analyzer over a pasted snippet, a file or a ZIP."""

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scans")
    name = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    files_scanned = models.PositiveIntegerField(default=0)
    score = models.PositiveSmallIntegerField(default=100)
    grade = models.CharField(max_length=1, default="A")
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    issues_truncated = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.grade}, {self.score}/100)"

    @property
    def total_issues(self):
        return self.high_count + self.medium_count + self.low_count


class Issue(models.Model):
    SEVERITY_CHOICES = [("HIGH", "High"), ("MEDIUM", "Medium"), ("LOW", "Low")]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="issues")
    rank = models.PositiveSmallIntegerField(default=2)  # 0 high, 1 medium, 2 low: used for sorting
    rule_id = models.CharField(max_length=40)
    title = models.CharField(max_length=200)
    severity = models.CharField(max_length=6, choices=SEVERITY_CHOICES)
    category = models.CharField(max_length=20)
    file_path = models.CharField(max_length=500)
    line = models.PositiveIntegerField(default=1)
    snippet = models.TextField(blank=True)
    detail = models.CharField(max_length=300, blank=True)
    fix = models.TextField(blank=True)

    class Meta:
        ordering = ["rank", "file_path", "line"]

    def __str__(self):
        return f"{self.rule_id} at {self.file_path}:{self.line}"
