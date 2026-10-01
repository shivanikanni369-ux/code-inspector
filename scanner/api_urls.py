from django.urls import include, path
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.routers import DefaultRouter

from . import api_views

router = DefaultRouter()
router.register("scans", api_views.ScanViewSet, basename="api-scan")

urlpatterns = [
    path("rules/", api_views.rule_list, name="api-rules"),
    path("token/", obtain_auth_token, name="api-token-obtain"),
    path("", include(router.urls)),
]
