from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer,
)


class AuthTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        # Get the standard refresh token
        token = super().get_token(user)

        # 🔧 Add custom claims
        token["email"] = user.email
        token["role"] = user.role if hasattr(user, "role") else "user"

        return token


class AuthTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        super().validate(attrs)
        # try:
        #     refresh = RefreshToken(attrs['refresh'])

        #     # 🔐 Optional: check a custom claim
        #     if refresh.get('blocked', False):
        #         raise serializers.ValidationError('This token is from a blocked user.')

        #     # Continue default validation
        #     data = {'access': str(refresh.access_token)}

        #     return data

        # except TokenError as e:
        #     raise serializers.ValidationError({'detail': 'Invalid or expired refresh token.'})
