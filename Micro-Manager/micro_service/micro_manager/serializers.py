from typing import TypeVar
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer, 
    TokenObtainSlidingSerializer,
    TokenRefreshSerializer,
    TokenRefreshSlidingSerializer,
    TokenVerifySerializer,
    TokenBlacklistSerializer
)
from .tokens import (
    ServiceRefreshToken
)
from django.utils.translation import gettext_lazy as _
from .tokens import ServiceRefreshToken, ServiceSlidingToken, ServiceToken
from rest_framework_simplejwt.models import TokenUser


AuthUser = TypeVar("AuthUser", bound=TokenUser)


class ServiceTokenObtainPairSerializer(TokenObtainPairSerializer):
    token_class = ServiceRefreshToken
    
    @classmethod
    def get_token(cls, user: AuthUser) -> ServiceToken:
        # Get the standard refresh token
        token = cls.token_class.for_user(user)

        # 🔧 Add custom claims
        token["name"] = user.name
        token['is_staff'] = user.is_staff
        token['is_superuser'] = user.is_superuser

        return token

class ServiceTokenObtainSlidingSerializer(TokenObtainSlidingSerializer):
    token_class = ServiceSlidingToken
    
    @classmethod
    def get_token(cls, user: AuthUser) -> ServiceToken:
        # Get the standard refresh token
        token = cls.token_class.for_user(user)

        # 🔧 Add custom claims
        token["name"] = user.name
        token['is_staff'] = user.is_staff
        token['is_superuser'] = user.is_superuser


        return token

class ServiceTokenRefreshSerializer(TokenRefreshSerializer):
    token_class = ServiceRefreshToken
    default_error_messages = {
        "no_active_service": _("No active service found for the given token.")
    }

class ServiceTokenRefreshSlidingSerializer(TokenRefreshSlidingSerializer):
    token_class = ServiceSlidingToken

class ServiceTokenVerifySerializer(TokenVerifySerializer):
    pass 

class ServiceTokenBlacklistSerializer(TokenBlacklistSerializer):
    token_class = ServiceRefreshToken