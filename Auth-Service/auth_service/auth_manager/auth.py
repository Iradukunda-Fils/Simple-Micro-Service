from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import get_user_model


# Get the user model
User = get_user_model()


class JWTAuth(JWTAuthentication):
    def get_user(self, validated_token):
        user = super().get_user(validated_token)

        # # Extra custom logic
        # if not getattr(user, 'is_admin', False) or not user.is_active:
        #     raise AuthenticationFailed("User account is inactive or lacks admin access.")
        return user

    # def authenticate(self, request):
    #     """
    #     Override this to control the full authentication process.
    #     """
    #     header = self.get_header(request)
    #     if header is None:
    #         return None  # no token provided

    #     raw_token = self.get_raw_token(header)
    #     if raw_token is None:
    #         return None

    #     try:
    #         validated_token = self.get_validated_token(raw_token)

    #         # Optional custom validation
    #         if validated_token.get("blocked", False):
    #             raise AuthenticationFailed("Token is from a blocked session.")

    #     except Exception as e:
    #         raise AuthenticationFailed(f"Token error: {str(e)}")

    #     user = self.get_user(validated_token)

    #     return (user, validated_token)
