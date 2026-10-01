from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from rest_framework.authtoken.models import Token

from .forms import ScanForm
from .models import Scan
from .pdf_report import build_scan_pdf
from .services import create_scan


def signup(request):
    if request.user.is_authenticated:
        return redirect("dashboard")
    form = UserCreationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        login(request, user)
        return redirect("dashboard")
    return render(request, "registration/signup.html", {"form": form})


@login_required
def dashboard(request):
    return render(request, "scanner/dashboard.html", {"scans": request.user.scans.all()})


@login_required
def new_scan(request):
    form = ScanForm(request.POST or None, request.FILES or None)
    if request.method == "POST" and form.is_valid():
        scan = create_scan(request.user, form.scan_name(), form.files)
        return redirect("scan_detail", pk=scan.pk)
    return render(request, "scanner/scan_form.html", {"form": form})


@login_required
def scan_detail(request, pk):
    scan = get_object_or_404(Scan, pk=pk, owner=request.user)
    severity = request.GET.get("severity", "").upper()
    issues = scan.issues.all()
    if severity in ("HIGH", "MEDIUM", "LOW"):
        issues = issues.filter(severity=severity)
    else:
        severity = ""

    total = max(scan.total_issues, 1)
    bars = [
        {"label": "High", "key": "high", "count": scan.high_count, "pct": round(100 * scan.high_count / total)},
        {"label": "Medium", "key": "medium", "count": scan.medium_count, "pct": round(100 * scan.medium_count / total)},
        {"label": "Low", "key": "low", "count": scan.low_count, "pct": round(100 * scan.low_count / total)},
    ]
    context = {"scan": scan, "issues": issues, "bars": bars, "active_severity": severity}
    return render(request, "scanner/scan_detail.html", context)


@login_required
def scan_json(request, pk):
    scan = get_object_or_404(Scan, pk=pk, owner=request.user)
    payload = {
        "name": scan.name,
        "created_at": scan.created_at.isoformat(),
        "score": scan.score,
        "grade": scan.grade,
        "files_scanned": scan.files_scanned,
        "counts": {"high": scan.high_count, "medium": scan.medium_count, "low": scan.low_count},
        "issues": list(
            scan.issues.values("rule_id", "title", "severity", "category", "file_path", "line", "snippet", "detail", "fix")
        ),
    }
    response = JsonResponse(payload, json_dumps_params={"indent": 2})
    response["Content-Disposition"] = f'attachment; filename="scan-{scan.pk}-report.json"'
    return response


@login_required
def scan_pdf(request, pk):
    scan = get_object_or_404(Scan, pk=pk, owner=request.user)
    pdf_bytes = build_scan_pdf(scan)
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="scan-{scan.pk}-report.pdf"'
    return response


@login_required
@require_POST
def scan_delete(request, pk):
    scan = get_object_or_404(Scan, pk=pk, owner=request.user)
    scan.delete()
    messages.success(request, "Scan deleted.")
    return redirect("dashboard")


@login_required
def api_token(request):
    token, _ = Token.objects.get_or_create(user=request.user)
    return render(request, "scanner/api_token.html", {"token": token.key})


@login_required
@require_POST
def api_token_regenerate(request):
    Token.objects.filter(user=request.user).delete()
    Token.objects.create(user=request.user)
    messages.success(request, "New API token generated. The old one no longer works.")
    return redirect("api_token")
