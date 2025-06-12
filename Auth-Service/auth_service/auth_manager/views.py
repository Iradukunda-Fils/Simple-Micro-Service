from rest_framework_simplejwt.views import TokenViewBase
from django.contrib.auth import login, logout
from rest_framework_simplejwt.tokens import RefreshToken
from .auth.serializers import TokenObtainPairSerializer, TokenObtainSlidingSerializer 
from rest_framework_simplejwt.serializers import TokenBlacklistSerializer

from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken


class AuthTokenObtainPairView(TokenViewBase):
    """
    Custom Token Obtain Pair View to handle token generation requests.
    """

    serializer_class = TokenObtainPairSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        # Use the user in serializer (not directly request.user)
        user = serializer.user

        # Log in the user to create a session (optional)
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


token_obtain_pair = AuthTokenObtainPairView.as_view()

class AuthTokenObtainSlidingView(TokenViewBase):
    """
    Custom Token Sliding Obtain View to handle token generation requests.
    """
    
    serializer_class = TokenObtainSlidingSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        # Use the user in serializer (not directly request.user)
        user = serializer.user

        # Log in the user to create a session (optional)
        login(request = request, user = user, backend = "django.contrib.auth.backends.ModelBackend")

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


token_obtain_sliding = AuthTokenObtainSlidingView.as_view()
    

class AuthTokenBlacklistView(TokenViewBase):
    """
    Custom view to blacklist a refresh token.
    """

    serializer_class = TokenBlacklistSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        # Optionally log the user out of session
        if request.user.is_authenticated and hasattr(request, "session"):
            logout(equest)

        return Response({}, status=status.HTTP_205_RESET_CONTENT)


token_blacklist = AuthTokenBlacklistView.as_view()
