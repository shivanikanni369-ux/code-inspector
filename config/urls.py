from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("django.contrib.auth.urls")),  # login, logout, password change
    path("api/", include("scanner.api_urls")),
    path("", include("scanner.urls")),
]
