from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .serializers import *


class AuthTokenView(TokenObtainPairView):
    """ "Custom Token Obtain Pair View to handle token generation requests.
    This view uses the AuthTokenObtainPairSerializer for validation.
    """

    serializer_class = AuthTokenObtainPairSerializer


class AuthTokenRefreshView(TokenRefreshView):
    """
    Custom Token Refresh View to handle token refresh requests.
    This view uses the AuthTokenRefreshSerializer for validation.
    """

    serializer_class = AuthTokenRefreshSerializer
