"""
URL configuration for auth_service project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse, JsonResponse

urlpatterns = [
    path("", lambda request: HttpResponse("<center><h1>Hello, World!</h1></center>")),
    path("health/", lambda request: JsonResponse({"status": "ok"})),
    path("admin/", admin.site.urls),
    path("api/", include("api.urls")),
    path("core/", include("core.urls")),
    path("api/token/", include(("auth_manager.urls", "auth_m"))),
]
