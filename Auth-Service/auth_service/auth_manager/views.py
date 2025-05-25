from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import AuthTokenObtainPairSerializer

class AuthTokenView(TokenObtainPairView):
    serializer_class = AuthTokenObtainPairSerializer
