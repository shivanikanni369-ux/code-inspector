from django.contrib import admin

from .models import Issue, Scan


class IssueInline(admin.TabularInline):
    model = Issue
    extra = 0
    fields = ("severity", "rule_id", "file_path", "line")
    readonly_fields = fields
    can_delete = False
    max_num = 0


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "grade", "score", "high_count", "medium_count", "low_count", "created_at")
    list_filter = ("grade",)
    inlines = [IssueInline]
