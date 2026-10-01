from django.http import HttpResponse
from rest_framework import mixins, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response

from .analyzer.rules import RULES
from .models import Scan
from .pdf_report import build_scan_pdf
from .serializers import ScanCreateSerializer, ScanDetailSerializer, ScanSummarySerializer
from .services import create_scan


class ScanViewSet(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    viewsets.GenericViewSet,
):
    """Create a scan, list your scans, fetch one report, delete a scan.

    Every query is filtered by the logged-in user, so other people's scans are never visible.
    """

    parser_classes = [JSONParser, MultiPartParser, FormParser]

    def get_queryset(self):
        queryset = Scan.objects.filter(owner=self.request.user)
        if self.action == "retrieve":
            queryset = queryset.prefetch_related("issues")
        return queryset

    def get_serializer_class(self):
        if self.action == "create":
            return ScanCreateSerializer
        if self.action == "retrieve":
            return ScanDetailSerializer
        return ScanSummarySerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        scan = create_scan(request.user, data["scan_name"], data["files"])
        return Response(ScanDetailSerializer(scan).data, status=201)

    @action(detail=True, methods=["get"], url_path="report.pdf")
    def report_pdf(self, request, pk=None):
        scan = self.get_object()
        pdf_bytes = build_scan_pdf(scan)
        response = HttpResponse(pdf_bytes, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="scan-{scan.pk}-report.pdf"'
        return response


@api_view(["GET"])
def rule_list(request):
    """The catalogue of checks the analyzer runs."""
    return Response(
        [
            {"id": r.id, "title": r.title, "severity": r.severity, "category": r.category, "fix": r.fix}
            for r in RULES.values()
        ]
    )
