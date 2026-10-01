from django.urls import path

from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("signup/", views.signup, name="signup"),
    path("scan/new/", views.new_scan, name="new_scan"),
    path("scan/<int:pk>/", views.scan_detail, name="scan_detail"),
    path("scan/<int:pk>/report.json", views.scan_json, name="scan_json"),
    path("scan/<int:pk>/report.pdf", views.scan_pdf, name="scan_pdf"),
    path("scan/<int:pk>/delete/", views.scan_delete, name="scan_delete"),
    path("api-token/", views.api_token, name="api_token"),
    path("api-token/regenerate/", views.api_token_regenerate, name="api_token_regenerate"),
]
