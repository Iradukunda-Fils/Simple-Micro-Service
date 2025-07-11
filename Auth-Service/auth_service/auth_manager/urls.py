from django.urls import path
from .views import (
    token_obtain_pair, 
    token_obtain_sliding, 
    token_blacklist
)
from rest_framework_simplejwt.views import (
    token_refresh,
    token_refresh_sliding,
    token_verify,
)

app = "auth_m"

urlpatterns = [
    path('', token_obtain_pair, name='obtain_pair'),
    path('refresh/', token_refresh, name='refresh'),
    path('sliding/', token_obtain_sliding, name='obtain_sliding'),
    path('sliding/refresh/', token_refresh_sliding, name='refresh_sliding'),
    path('verify/', token_verify, name='verify'),
    path('blacklist/', token_blacklist, name='blacklist'),
]

