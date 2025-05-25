from rest_framework import status
from rest_framework.exceptions import APIException

class TokenException(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = 'Token error occurred'
    default_code = 'token_error'

class InvalidTokenException(TokenException):
    default_detail = 'Invalid token provided'
    default_code = 'invalid_token'

class ExpiredTokenException(TokenException):
    default_detail = 'Token has expired'
    default_code = 'token_expired'

class KeyLoadException(Exception):
    """Exception raised when cryptographic keys cannot be loaded"""
    pass

class UnsupportedAlgorithmException(Exception):
    """Exception raised when an unsupported algorithm is requested"""
    pass