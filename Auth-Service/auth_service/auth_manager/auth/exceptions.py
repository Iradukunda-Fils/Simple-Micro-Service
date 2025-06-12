from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework.exceptions import AuthenticationFailed


class InvalidTokenType(TokenError):
    pass


def validate_token_type(token, expected_type="refresh"):
    try:
        untyped_token = UntypedToken(token)
        token_type = untyped_token.payload.get("token_type", None)
        if token_type != expected_type:
            raise InvalidToken(f"Invalid token type: expected '{expected_type}', got '{token_type}'")
    except TokenError as e:
        raise AuthenticationFailed("Invalid token.") from e
