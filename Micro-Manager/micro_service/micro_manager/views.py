from django.contrib.auth import logout, login
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.views import (
    TokenViewBase,
    TokenRefreshView,
    TokenVerifyView,
)

from .serializers import (
    ServiceTokenBlacklistSerializer,
    ServiceTokenObtainPairSerializer,
    ServiceTokenObtainSlidingSerializer,
    ServiceTokenRefreshSlidingSerializer
)



class TokenObtainPairView(TokenViewBase):
    """
    Takes a set of user credentials and returns an access and refresh JSON web
    token pair to prove the authentication of those credentials.
    """
    
    serializer_class = ServiceTokenObtainPairSerializer
    
    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        # Use the user in serializer (not directly request.user)
        user = serializer.user
        
        if user:
            # Log in the user to create a session (optional)
            login(request = request, user = user, 
                backend = "django.contrib.auth.backends.ModelBackend"
                )

        return Response(serializer.validated_data, status=status.HTTP_200_OK)
    

class TokenObtainSlidingView(TokenViewBase):
    """
    Custom Token Sliding Obtain View to handle token generation requests.
    """
    
    serializer_class  = ServiceTokenObtainSlidingSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        # Use the user in serializer (not directly request.user)
        user = serializer.user

        if user:
            # Log in the user to create a session (optional)
            login(
                request = request, user = user, 
                backend = "django.contrib.auth.backends.ModelBackend"
                )

        return Response(serializer.validated_data, status=status.HTTP_200_OK)



class TokenBlacklistView(TokenViewBase):
    """
    Custom view to blacklist a refresh token.
    """
    
    serializer_class = ServiceTokenBlacklistSerializer

    def post(self, request: Request, *args, **kwargs) -> Response:
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        # Optionally log the user out of session
        if request.user.is_authenticated and hasattr(request, "session"):
            logout(equest)

        return Response(serializer.validated_data, status=status.HTTP_200_OK)
    
class TokenRefreshSlidingView(TokenViewBase):
    serializer_class = ServiceTokenRefreshSlidingSerializer
    

token_obtain_pair = TokenObtainPairView.as_view()

token_refresh = TokenRefreshView.as_view()

token_obtain_sliding = TokenObtainSlidingView.as_view()

token_refresh_sliding = TokenRefreshSlidingView.as_view()

token_verify = TokenVerifyView.as_view()

token_blacklist = TokenBlacklistView.as_view()