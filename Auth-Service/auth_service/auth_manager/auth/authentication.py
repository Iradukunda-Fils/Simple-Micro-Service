from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import get_user_model


# Get the user model
User = get_user_model()


class UserJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        user = super().get_user(validated_token)
        return user

