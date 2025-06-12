from typing import TypeVar
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer as BaseObtainPairs,
    TokenObtainSlidingSerializer as BaseSliding
    )
from rest_framework_simplejwt.tokens import RefreshToken, SlidingToken, Token
from rest_framework_simplejwt.models import TokenUser

AuthUser = TypeVar("AuthUser", bound=TokenUser)

class TokenObtainPairSerializer(BaseObtainPairs):
    token_class = RefreshToken

    @classmethod
    def get_token(cls, user: AuthUser) -> Token:
        # Get the standard refresh token
        token = cls.token_class.for_user(user)

        # 🔧 Add custom claims
        token["email"] = user.email
        token["username"] = user.username
        token["is_active"] = user.is_active
        token["role"] = user.role if hasattr(user, "role") else "user"

        return token
    

class TokenObtainSlidingSerializer(BaseSliding):
    @classmethod
    def get_token(cls, user: AuthUser) -> Token:
        # Get the standard refresh token
        token = cls.token_class.for_user(user)

        # 🔧 Add custom claims
        token["email"] = user.email
        token["username"] = user.username
        token["is_active"] = user.is_active
        token["role"] = user.role if hasattr(user, "role") else "user"

        return token



