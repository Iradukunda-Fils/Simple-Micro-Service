# # settings.py - Configuration
# from pathlib import Path
# from datetime import timedelta

# BASE_DIR = Path(__file__).resolve().parent.parent

# # JWT Configuration
# JWT_SETTINGS = {
#     'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
#     'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
#     'ROTATE_REFRESH_TOKENS': True,
#     'BLACKLIST_AFTER_ROTATION': True,
#     'ALGORITHM': 'RS256',  # RSA with SHA-256
#     'SIGNING_KEY_PATH': BASE_DIR / 'keys' / 'private_key.pem',
#     'VERIFYING_KEY_PATH': BASE_DIR / 'keys' / 'public_key.pem',
#     'AUDIENCE': ['bank-service', 'auth-service'],
#     'ISSUER': 'auth-service',
# }

# # Alternative algorithms configuration
# CRYPTO_ALGORITHMS = {
#     'RSA': {
#         'sign': 'RS256',
#         'private_key_file': 'rsa_private_key.pem',
#         'public_key_file': 'rsa_public_key.pem',
#     },
#     'ECDSA': {
#         'sign': 'ES256',
#         'private_key_file': 'ecdsa_private_key.pem',
#         'public_key_file': 'ecdsa_public_key.pem',
#     },
#     'EdDSA': {
#         'sign': 'EdDSA',
#         'private_key_file': 'ed25519_private_key.pem',
#         'public_key_file': 'ed25519_public_key.pem',
#     }
# }

# INSTALLED_APPS = [
#     'django.contrib.admin',
#     'django.contrib.auth',
#     'django.contrib.contenttypes',
#     'django.contrib.sessions',
#     'django.contrib.messages',
#     'django.contrib.staticfiles',
#     'rest_framework',
#     'rest_framework_simplejwt',
#     'rest_framework_simplejwt.token_blacklist',
#     'authentication',
#     'corsheaders',
# ]

# REST_FRAMEWORK = {
#     'DEFAULT_AUTHENTICATION_CLASSES': (
#         'authentication.backends.AsymmetricJWTAuthentication',
#     ),
#     'DEFAULT_PERMISSION_CLASSES': [
#         'rest_framework.permissions.IsAuthenticated',
#     ],
#     'DEFAULT_RENDERER_CLASSES': [
#         'rest_framework.renderers.JSONRenderer',
#     ],
#     'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
#     'PAGE_SIZE': 20
# }

# # Cache configuration for token blacklisting
# CACHES = {
#     'default': {
#         'BACKEND': 'django_redis.cache.RedisCache',
#         'LOCATION': 'redis://127.0.0.1:6379/1',
#         'OPTIONS': {
#             'CLIENT_CLASS': 'django_redis.client.DefaultClient',
#         }
#     }
# }

# # Security settings
# SECURE_SSL_REDIRECT = True
# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
# SECURE_HSTS_SECONDS = 31536000
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# SECURE_HSTS_PRELOAD = True

# # ==================================================
# # authentication/types.py - Type definitions
# from typing import Protocol, Dict, Any, Optional
# from dataclasses import dataclass
# from enum import Enum

# class AlgorithmType(str, Enum):
#     RSA = "RSA"
#     ECDSA = "ECDSA"
#     EdDSA = "EdDSA"

# class JWTAlgorithm(str, Enum):
#     RS256 = "RS256"
#     ES256 = "ES256"
#     EdDSA = "EdDSA"

# @dataclass(frozen=True)
# class TokenPayload:
#     user_id: int
#     username: str
#     email: str
#     service: str
#     permissions: list[str]
#     iat: int
#     exp: int
#     aud: list[str]
#     iss: str
#     jti: str

# @dataclass(frozen=True)
# class KeyConfig:
#     algorithm_type: AlgorithmType
#     jwt_algorithm: JWTAlgorithm
#     private_key_path: str
#     public_key_path: str

# class CryptoKeyManagerProtocol(Protocol):
#     def load_private_key(self, key_path: str) -> Any: ...
#     def load_public_key(self, key_path: str) -> Any: ...
#     def sign_token(self, payload: Dict[str, Any]) -> str: ...
#     def verify_token(self, token: str) -> Dict[str, Any]: ...

# # ==================================================
# # authentication/exceptions.py - Custom exceptions
# from rest_framework import status
# from rest_framework.exceptions import APIException

# class TokenException(APIException):
#     status_code = status.HTTP_401_UNAUTHORIZED
#     default_detail = 'Token error occurred'
#     default_code = 'token_error'

# class InvalidTokenException(TokenException):
#     default_detail = 'Invalid token provided'
#     default_code = 'invalid_token'

# class ExpiredTokenException(TokenException):
#     default_detail = 'Token has expired'
#     default_code = 'token_expired'

# class KeyLoadException(Exception):
#     """Exception raised when cryptographic keys cannot be loaded"""
#     pass

# class UnsupportedAlgorithmException(Exception):
#     """Exception raised when an unsupported algorithm is requested"""
#     pass

# # ==================================================
# # authentication/crypto/key_manager.py - Key Management
# import jwt
# import logging
# from pathlib import Path
# from typing import Any, Dict
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
# from django.conf import settings
# from django.core.cache import cache

# from ..types import AlgorithmType, JWTAlgorithm, KeyConfig
# from ..exceptions import KeyLoadException, UnsupportedAlgorithmException

# logger = logging.getLogger(__name__)

# class CryptoKeyManager:
#     """
#     Manages cryptographic keys for JWT signing and verification.
#     Supports RSA, ECDSA, and EdDSA algorithms with caching optimization.
#     """
    
#     def __init__(self, algorithm_type: AlgorithmType):
#         self.algorithm_type = algorithm_type
#         self.config = self._get_algorithm_config()
#         self._private_key: Optional[Any] = None
#         self._public_key: Optional[Any] = None
        
#     def _get_algorithm_config(self) -> KeyConfig:
#         """Get configuration for the specified algorithm type."""
#         algo_configs = getattr(settings, 'CRYPTO_ALGORITHMS', {})
        
#         if self.algorithm_type not in algo_configs:
#             raise UnsupportedAlgorithmException(
#                 f"Algorithm {self.algorithm_type} is not supported"
#             )
            
#         config = algo_configs[self.algorithm_type]
#         return KeyConfig(
#             algorithm_type=self.algorithm_type,
#             jwt_algorithm=JWTAlgorithm(config['sign']),
#             private_key_path=str(settings.BASE_DIR / 'keys' / config['private_key_file']),
#             public_key_path=str(settings.BASE_DIR / 'keys' / config['public_key_file'])
#         )
    
#     @property
#     def private_key(self) -> Any:
#         """Lazy load and cache private key."""
#         if self._private_key is None:
#             cache_key = f"private_key_{self.algorithm_type}"
#             self._private_key = cache.get(cache_key)
            
#             if self._private_key is None:
#                 self._private_key = self._load_private_key()
#                 cache.set(cache_key, self._private_key, timeout=3600)  # 1 hour
                
#         return self._private_key
    
#     @property 
#     def public_key(self) -> Any:
#         """Lazy load and cache public key."""
#         if self._public_key is None:
#             cache_key = f"public_key_{self.algorithm_type}"
#             self._public_key = cache.get(cache_key)
            
#             if self._public_key is None:
#                 self._public_key = self._load_public_key()
#                 cache.set(cache_key, self._public_key, timeout=3600)  # 1 hour
                
#         return self._public_key
    
#     def _load_private_key(self) -> Any:
#         """Load private key based on algorithm type."""
#         try:
#             key_path = Path(self.config.private_key_path)
#             if not key_path.exists():
#                 raise KeyLoadException(f"Private key file not found: {key_path}")
                
#             with open(key_path, 'rb') as key_file:
#                 key_data = key_file.read()
                
#             return serialization.load_pem_private_key(
#                 key_data, 
#                 password=None
#             )
            
#         except Exception as e:
#             logger.error(f"Failed to load private key for {self.algorithm_type}: {e}")
#             raise KeyLoadException(f"Could not load private key: {e}")
    
#     def _load_public_key(self) -> Any:
#         """Load public key based on algorithm type."""
#         try:
#             key_path = Path(self.config.public_key_path)
#             if not key_path.exists():
#                 raise KeyLoadException(f"Public key file not found: {key_path}")
                
#             with open(key_path, 'rb') as key_file:
#                 key_data = key_file.read()
                
#             return serialization.load_pem_public_key(key_data)
            
#         except Exception as e:
#             logger.error(f"Failed to load public key for {self.algorithm_type}: {e}")
#             raise KeyLoadException(f"Could not load public key: {e}")
    
#     def sign_token(self, payload: Dict[str, Any]) -> str:
#         """Sign JWT token with private key."""
#         try:
#             return jwt.encode(
#                 payload=payload,
#                 key=self.private_key,
#                 algorithm=self.config.jwt_algorithm.value
#             )
#         except Exception as e:
#             logger.error(f"Token signing failed: {e}")
#             raise InvalidTokenException("Failed to sign token")
    
#     def verify_token(self, token: str, audience: Optional[list[str]] = None) -> Dict[str, Any]:
#         """Verify JWT token with public key."""
#         try:
#             return jwt.decode(
#                 jwt=token,
#                 key=self.public_key,
#                 algorithms=[self.config.jwt_algorithm.value],
#                 audience=audience,
#                 issuer=getattr(settings, 'JWT_SETTINGS', {}).get('ISSUER')
#             )
#         except jwt.ExpiredSignatureError:
#             raise ExpiredTokenException("Token has expired")
#         except jwt.InvalidTokenError as e:
#             logger.warning(f"Token verification failed: {e}")
#             raise InvalidTokenException("Invalid token")

# # ==================================================
# # authentication/managers/token_manager.py - Token Management
# import uuid
# from datetime import datetime, timezone
# from typing import Dict, Any, Optional
# from django.contrib.auth.models import User

# from ..crypto.key_manager import CryptoKeyManager
# from ..types import AlgorithmType, TokenPayload
# from ..exceptions import InvalidTokenException

# class JWTTokenManager:
#     """
#     Manages JWT token creation, validation, and blacklisting.
#     Implements token rotation and security best practices.
#     """
    
#     def __init__(self, algorithm_type: AlgorithmType = AlgorithmType.RSA):
#         self.key_manager = CryptoKeyManager(algorithm_type)
#         self.jwt_settings = getattr(settings, 'JWT_SETTINGS', {})
    
#     def create_access_token(self, user: User, service: str, permissions: list[str]) -> str:
#         """Create a new access token for the user."""
#         now = datetime.now(timezone.utc)
#         exp = now + self.jwt_settings.get('ACCESS_TOKEN_LIFETIME')
        
#         payload = {
#             'user_id': user.id,
#             'username': user.username,
#             'email': user.email,
#             'service': service,
#             'permissions': permissions,
#             'iat': int(now.timestamp()),
#             'exp': int(exp.timestamp()),
#             'aud': self.jwt_settings.get('AUDIENCE', []),
#             'iss': self.jwt_settings.get('ISSUER'),
#             'jti': str(uuid.uuid4()),
#             'token_type': 'access'
#         }
        
#         return self.key_manager.sign_token(payload)
    
#     def create_refresh_token(self, user: User, service: str) -> str:
#         """Create a new refresh token for the user."""
#         now = datetime.now(timezone.utc)
#         exp = now + self.jwt_settings.get('REFRESH_TOKEN_LIFETIME')
        
#         payload = {
#             'user_id': user.id,
#             'username': user.username,
#             'service': service,
#             'iat': int(now.timestamp()),
#             'exp': int(exp.timestamp()),
#             'aud': self.jwt_settings.get('AUDIENCE', []),
#             'iss': self.jwt_settings.get('ISSUER'),
#             'jti': str(uuid.uuid4()),
#             'token_type': 'refresh'
#         }
        
#         return self.key_manager.sign_token(payload)
    
#     def verify_token(self, token: str) -> TokenPayload:
#         """Verify and decode JWT token."""
#         # Check if token is blacklisted
#         if self.is_token_blacklisted(token):
#             raise InvalidTokenException("Token has been revoked")
        
#         payload = self.key_manager.verify_token(
#             token=token,
#             audience=self.jwt_settings.get('AUDIENCE')
#         )
        
#         return TokenPayload(
#             user_id=payload['user_id'],
#             username=payload['username'],
#             email=payload['email'],
#             service=payload['service'],
#             permissions=payload.get('permissions', []),
#             iat=payload['iat'],
#             exp=payload['exp'],
#             aud=payload['aud'],
#             iss=payload['iss'],
#             jti=payload['jti']
#         )
    
#     def blacklist_token(self, token: str) -> None:
#         """Add token to blacklist."""
#         try:
#             payload = self.key_manager.verify_token(token)
#             jti = payload.get('jti')
#             exp = payload.get('exp')
            
#             if jti and exp:
#                 # Calculate TTL based on token expiration
#                 ttl = exp - int(datetime.now(timezone.utc).timestamp())
#                 if ttl > 0:
#                     cache.set(f"blacklist_{jti}", True, timeout=ttl)
                    
#         except Exception:
#             # If token is invalid, we don't need to blacklist it
#             pass
    
#     def is_token_blacklisted(self, token: str) -> bool:
#         """Check if token is blacklisted."""
#         try:
#             payload = self.key_manager.verify_token(token)
#             jti = payload.get('jti')
#             return bool(cache.get(f"blacklist_{jti}"))
#         except Exception:
#             return False
    
#     def refresh_access_token(self, refresh_token: str) -> Dict[str, str]:
#         """Create new access token using refresh token."""
#         payload = self.verify_token(refresh_token)
        
#         if payload.token_type != 'refresh':
#             raise InvalidTokenException("Invalid refresh token")
        
#         # Get user
#         try:
#             user = User.objects.get(id=payload.user_id)
#         except User.DoesNotExist:
#             raise InvalidTokenException("User not found")
        
#         # Create new tokens
#         new_access_token = self.create_access_token(
#             user=user,
#             service=payload.service,
#             permissions=payload.permissions
#         )
        
#         new_refresh_token = None
#         if self.jwt_settings.get('ROTATE_REFRESH_TOKENS'):
#             new_refresh_token = self.create_refresh_token(user, payload.service)
            
#             if self.jwt_settings.get('BLACKLIST_AFTER_ROTATION'):
#                 self.blacklist_token(refresh_token)
        
#         result = {'access_token': new_access_token}
#         if new_refresh_token:
#             result['refresh_token'] = new_refresh_token
            
#         return result

# # ==================================================
# # authentication/backends.py - Custom Authentication Backend
# from typing import Optional, Tuple
# from django.contrib.auth.models import User
# from rest_framework.authentication import BaseAuthentication
# from rest_framework.request import Request

# from .managers.token_manager import JWTTokenManager
# from .types import AlgorithmType
# from .exceptions import InvalidTokenException, ExpiredTokenException

# class AsymmetricJWTAuthentication(BaseAuthentication):
#     """
#     Custom JWT authentication backend using asymmetric encryption.
#     Supports multiple cryptographic algorithms.
#     """
    
#     def __init__(self, algorithm_type: AlgorithmType = AlgorithmType.RSA):
#         self.token_manager = JWTTokenManager(algorithm_type)
    
#     def authenticate(self, request: Request) -> Optional[Tuple[User, str]]:
#         """Authenticate user based on JWT token."""
#         token = self.get_token_from_request(request)
#         if not token:
#             return None
        
#         try:
#             payload = self.token_manager.verify_token(token)
#             user = self.get_user_from_payload(payload)
            
#             if user:
#                 # Store token payload in request for later use
#                 request.token_payload = payload
#                 return (user, token)
                
#         except (InvalidTokenException, ExpiredTokenException):
#             pass
        
#         return None
    
#     def get_token_from_request(self, request: Request) -> Optional[str]:
#         """Extract token from request headers."""
#         auth_header = request.META.get('HTTP_AUTHORIZATION')
        
#         if not auth_header or not auth_header.startswith('Bearer '):
#             return None
        
#         return auth_header.split(' ')[1]
    
#     def get_user_from_payload(self, payload) -> Optional[User]:
#         """Get user instance from token payload."""
#         try:
#             return User.objects.get(id=payload.user_id, is_active=True)
#         except User.DoesNotExist:
#             return None
    
#     def authenticate_header(self, request: Request) -> str:
#         """Return authentication header for 401 responses."""
#         return 'Bearer realm="api"'

# # ==================================================
# # authentication/permissions.py - Custom Permissions
# from rest_framework.permissions import BasePermission
# from rest_framework.request import Request
# from rest_framework.views import View

# class ServicePermission(BasePermission):
#     """
#     Permission class to check service-specific access.
#     """
    
#     def __init__(self, required_service: str):
#         self.required_service = required_service
    
#     def has_permission(self, request: Request, view: View) -> bool:
#         if not hasattr(request, 'token_payload'):
#             return False
        
#         return request.token_payload.service == self.required_service

# class PermissionBasedAccess(BasePermission):
#     """
#     Permission class to check specific permissions.
#     """
    
#     def __init__(self, required_permissions: list[str]):
#         self.required_permissions = required_permissions
    
#     def has_permission(self, request: Request, view: View) -> bool:
#         if not hasattr(request, 'token_payload'):
#             return False
        
#         user_permissions = set(request.token_payload.permissions)
#         required_permissions = set(self.required_permissions)
        
#         return required_permissions.issubset(user_permissions)

# # ==================================================
# # authentication/views.py - API Views
# from rest_framework import status
# from rest_framework.decorators import api_view
# from rest_framework.permissions import AllowAny
# from rest_framework.response import Response
# from rest_framework.views import APIView
# from django.contrib.auth import authenticate
# from django.contrib.auth.models import User

# from .types import AlgorithmType

# class AuthenticationView(APIView):
#     """
#     Handle user authentication and token generation.
#     """
#     permission_classes = [AllowAny]
    
#     def __init__(self):
#         super().__init__()
#         self.token_manager = JWTTokenManager(AlgorithmType.RSA)
    
#     def post(self, request):
#         """Authenticate user and return tokens."""
#         username = request.data.get('username')
#         password = request.data.get('password')
#         service = request.data.get('service', 'default')
        
#         if not username or not password:
#             return Response(
#                 {'error': 'Username and password required'},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
        
#         user = authenticate(username=username, password=password)
#         if not user:
#             return Response(
#                 {'error': 'Invalid credentials'},
#                 status=status.HTTP_401_UNAUTHORIZED
#             )
        
#         # Get user permissions (customize based on your needs)
#         permissions = self._get_user_permissions(user, service)
        
#         access_token = self.token_manager.create_access_token(
#             user=user,
#             service=service,
#             permissions=permissions
#         )
        
#         refresh_token = self.token_manager.create_refresh_token(
#             user=user,
#             service=service
#         )
        
#         return Response({
#             'access_token': access_token,
#             'refresh_token': refresh_token,
#             'token_type': 'Bearer',
#             'user': {
#                 'id': user.id,
#                 'username': user.username,
#                 'email': user.email
#             }
#         })
    
#     def _get_user_permissions(self, user: User, service: str) -> list[str]:
#         """Get user permissions for the specific service."""
#         # Implement your permission logic here
#         base_permissions = ['read']
        
#         if user.is_staff:
#             base_permissions.extend(['write', 'delete'])
        
#         if service == 'bank-service':
#             base_permissions.extend(['transfer', 'balance_inquiry'])
        
#         return base_permissions

# class TokenRefreshView(APIView):
#     """
#     Handle token refresh.
#     """
#     permission_classes = [AllowAny]
    
#     def __init__(self):
#         super().__init__()
#         self.token_manager = JWTTokenManager(AlgorithmType.RSA)
    
#     def post(self, request):
#         """Refresh access token using refresh token."""
#         refresh_token = request.data.get('refresh_token')
        
#         if not refresh_token:
#             return Response(
#                 {'error': 'Refresh token required'},
#                 status=status.HTTP_400_BAD_REQUEST
#             )
        
#         try:
#             tokens = self.token_manager.refresh_access_token(refresh_token)
#             return Response(tokens)
            
#         except InvalidTokenException as e:
#             return Response(
#                 {'error': str(e)},
#                 status=status.HTTP_401_UNAUTHORIZED
#             )

# class TokenRevokeView(APIView):
#     """
#     Handle token revocation.
#     """
    
#     def __init__(self):
#         super().__init__()
#         self.token_manager = JWTTokenManager(AlgorithmType.RSA)
    
#     def post(self, request):
#         """Revoke (blacklist) a token."""
#         token = request.data.get('token')
        
#         if not token:
#             # Try to get token from authorization header
#             auth_header = request.META.get('HTTP_AUTHORIZATION')
#             if auth_header and auth_header.startswith('Bearer '):
#                 token = auth_header.split(' ')[1]
        
#         if token:
#             self.token_manager.blacklist_token(token)
        
#         return Response({'message': 'Token revoked successfully'})

# @api_view(['GET'])
# def protected_view(request):
#     """
#     Example protected view that requires authentication.
#     """
#     payload = getattr(request, 'token_payload', None)
#     return Response({
#         'message': 'Access granted',
#         'user': payload.username if payload else 'Unknown',
#         'service': payload.service if payload else 'Unknown',
#         'permissions': payload.permissions if payload else []
#     })

# # ==================================================
# # authentication/urls.py - URL Configuration
# from django.urls import path
# from .views import (
#     AuthenticationView,
#     TokenRefreshView, 
#     TokenRevokeView,
#     protected_view
# )

# urlpatterns = [
#     path('login/', AuthenticationView.as_view(), name='login'),
#     path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
#     path('revoke/', TokenRevokeView.as_view(), name='token_revoke'),
#     path('protected/', protected_view, name='protected'),
# ]

# # ==================================================
# # management/commands/generate_keys.py - Key Generation Command
# from pathlib import Path
# from django.core.management.base import BaseCommand

# class Command(BaseCommand):
#     help = 'Generate cryptographic key pairs for JWT signing'
    
#     def add_arguments(self, parser):
#         parser.add_argument(
#             '--algorithm',
#             type=str,
#             choices=['RSA', 'ECDSA', 'EdDSA'],
#             default='RSA',
#             help='Algorithm type for key generation'
#         )
        
#     def handle(self, *args, **options):
#         algorithm = options['algorithm']
#         keys_dir = Path('keys')
#         keys_dir.mkdir(exist_ok=True)
        
#         if algorithm == 'RSA':
#             self._generate_rsa_keys(keys_dir)
#         elif algorithm == 'ECDSA':
#             self._generate_ecdsa_keys(keys_dir)
#         elif algorithm == 'EdDSA':
#             self._generate_ed25519_keys(keys_dir)
            
#         self.stdout.write(
#             self.style.SUCCESS(f'Successfully generated {algorithm} key pair')
#         )
    
#     def _generate_rsa_keys(self, keys_dir: Path):
#         private_key = rsa.generate_private_key(
#             public_exponent=65537,
#             key_size=2048
#         )
        
#         # Save private key
#         with open(keys_dir / 'rsa_private_key.pem', 'wb') as f:
#             f.write(private_key.private_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PrivateFormat.PKCS8,
#                 encryption_algorithm=serialization.NoEncryption()
#             ))
        
#         # Save public key
#         public_key = private_key.public_key()
#         with open(keys_dir / 'rsa_public_key.pem', 'wb') as f:
#             f.write(public_key.public_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PublicFormat.SubjectPublicKeyInfo
#             ))
    
#     def _generate_ecdsa_keys(self, keys_dir: Path):
#         private_key = ec.generate_private_key(ec.SECP256R1())
        
#         # Save private key
#         with open(keys_dir / 'ecdsa_private_key.pem', 'wb') as f:
#             f.write(private_key.private_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PrivateFormat.PKCS8,
#                 encryption_algorithm=serialization.NoEncryption()
#             ))
        
#         # Save public key
#         public_key = private_key.public_key()
#         with open(keys_dir / 'ecdsa_public_key.pem', 'wb') as f:
#             f.write(public_key.public_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PublicFormat.SubjectPublicKeyInfo
#             ))
    
#     def _generate_ed25519_keys(self, keys_dir: Path):
#         private_key = ed25519.Ed25519PrivateKey.generate()
        
#         # Save private key
#         with open(keys_dir / 'ed25519_private_key.pem', 'wb') as f:
#             f.write(private_key.private_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PrivateFormat.PKCS8,
#                 encryption_algorithm=serialization.NoEncryption()
#             ))
        
#         # Save public key
#         public_key = private_key.public_key()
#         with open(keys_dir / 'ed25519_public_key.pem', 'wb') as f:
#             f.write(public_key.public_bytes(
#                 encoding=serialization.Encoding.PEM,
#                 format=serialization.PublicFormat.SubjectPublicKeyInfo
#             ))

# # Usage Examples:
# # python manage.py generate_keys --algorithm RSA
# # python manage.py generate_keys --algorithm ECDSA  
# # python manage.py generate_keys --algorithm EdDSA

# # ==================================================
# # bank_service/authentication.py - Bank Service Token Verification
# from typing import Optional
# import requests
# from rest_framework.authentication import BaseAuthentication
# from rest_framework.request import Request

# from authentication.crypto.key_manager import CryptoKeyManager
# from authentication.types import AlgorithmType
# from authentication.exceptions import InvalidTokenException

# class BankServiceAuthentication(BaseAuthentication):
#     """
#     Authentication backend for Bank Service.
#     Verifies tokens issued by Auth Service using public key.
#     """
    
#     def __init__(self):
#         self.key_manager = CryptoKeyManager(AlgorithmType.RSA)
#         self.auth_service_url = getattr(settings, 'AUTH_SERVICE_URL', 'http://auth-service:8000')
    
#     def authenticate(self, request: Request):
#         """Authenticate using JWT token from Auth Service."""
#         token = self.get_token_from_request(request)
#         if not token:
#             return None
        
#         try:
#             # Verify token using public key
#             payload = self.key_manager.verify_token(
#                 token=token,
#                 audience=['bank-service']
#             )
            
#             # Validate service access
#             if payload.get('service') not in ['bank-service', 'all']:
#                 raise InvalidTokenException("Service access denied")
            
#             # Create user-like object for DRF compatibility
#             user = self.create_user_from_payload(payload)
#             request.token_payload = payload
            
#             return (user, token)
            
#         except Exception:
#             return None
    
#     def get_token_from_request(self, request: Request) -> Optional[str]:
#         """Extract Bearer token from Authorization header."""
#         auth_header = request.META.get('HTTP_AUTHORIZATION')
#         if not auth_header or not auth_header.startswith('Bearer '):
#             return None
#         return auth_header.split(' ')[1]
    
#     def create_user_from_payload(self, payload: dict):
#         """Create a user-like object from token payload."""
#         class TokenUser:
#             def __init__(self, payload):
#                 self.id = payload.get('user_id')
#                 self.username = payload.get('username')
#                 self.email = payload.get('email')
#                 self.permissions = payload.get('permissions', [])
#                 self.is_authenticated = True
#                 self.is_anonymous = False
            
#             def has_perm(self, permission: str) -> bool:
#                 return permission in self.permissions
        
#         return TokenUser(payload)

# # ==================================================
# # bank_service/views.py - Bank Service Protected Views
# from rest_framework.views import APIView
# from rest_framework import status
# from rest_framework.decorators import api_view
# from decimal import Decimal

# from .authentication import BankServiceAuthentication

# class AccountBalanceView(APIView):
#     """
#     Protected endpoint for checking account balance.
#     Requires 'balance_inquiry' permission.
#     """
#     authentication_classes = [BankServiceAuthentication]
    
#     def get(self, request):
#         # Check if user has required permission
#         if not request.user.has_perm('balance_inquiry'):
#             return Response(
#                 {'error': 'Insufficient permissions'}, 
#                 status=status.HTTP_403_FORBIDDEN
#             )
        
#         # Mock balance data
#         balance_data = {
#             'account_id': f"ACC_{request.user.id}",
#             'balance': Decimal('1500.50'),
#             'currency': 'USD',
#             'user': request.user.username,
#             'timestamp': '2025-05-24T10:30:00Z'
#         }
        
#         return Response(balance_data)

# class TransferFundsView(APIView):
#     """
#     Protected endpoint for fund transfers.
#     Requires 'transfer' permission.
#     """
#     authentication_classes = [BankServiceAuthentication]
    
#     def post(self, request):
#         if not request.user.has_perm('transfer'):
#             return Response(
#                 {'error': 'Transfer permission required'}, 
#                 status=status.HTTP_403_FORBIDDEN
#             )
        
#         # Mock transfer logic
#         transfer_data = {
#             'transaction_id': f"TXN_{request.user.id}_001",
#             'from_account': f"ACC_{request.user.id}",
#             'to_account': request.data.get('to_account'),
#             'amount': request.data.get('amount'),
#             'status': 'completed',
#             'timestamp': '2025-05-24T10:35:00Z'
#         }
        
#         return Response(transfer_data, status=status.HTTP_201_CREATED)

# # ==================================================
# # utils/service_client.py - Inter-Service Communication Helper
# from typing import Dict, Any, Optional
# import logging

# logger = logging.getLogger(__name__)

# class ServiceClient:
#     """
#     Helper class for making authenticated requests between microservices.
#     """
    
#     def __init__(self, service_name: str, base_url: str):
#         self.service_name = service_name
#         self.base_url = base_url.rstrip('/')
#         self.session = requests.Session()
    
#     def set_token(self, token: str) -> None:
#         """Set authentication token for requests."""
#         self.session.headers.update({
#             'Authorization': f'Bearer {token}',
#             'Content-Type': 'application/json'
#         })
    
#     def get(self, endpoint: str, params: Optional[Dict] = None) -> requests.Response:
#         """Make authenticated GET request."""
#         url = f"{self.base_url}/{endpoint.lstrip('/')}"
#         return self.session.get(url, params=params)
    
#     def post(self, endpoint: str, data: Optional[Dict] = None) -> requests.Response:
#         """Make authenticated POST request."""
#         url = f"{self.base_url}/{endpoint.lstrip('/')}"
#         return self.session.post(url, json=data)
    
#     def put(self, endpoint: str, data: Optional[Dict] = None) -> requests.Response:
#         """Make authenticated PUT request."""
#         url = f"{self.base_url}/{endpoint.lstrip('/')}"
#         return self.session.put(url, json=data)
    
#     def delete(self, endpoint: str) -> requests.Response:
#         """Make authenticated DELETE request."""
#         url = f"{self.base_url}/{endpoint.lstrip('/')}"
#         return self.session.delete(url)

# # Example usage in views
# class BankServiceClient:
#     """Bank service specific client."""
    
#     def __init__(self, token: str):
#         self.client = ServiceClient(
#             service_name='bank-service',
#             base_url=settings.BANK_SERVICE_URL
#         )
#         self.client.set_token(token)
    
#     def get_balance(self, account_id: str) -> Dict[str, Any]:
#         """Get account balance from bank service."""
#         response = self.client.get(f'/api/accounts/{account_id}/balance/')
#         response.raise_for_status()
#         return response.json()
    
#     def transfer_funds(self, transfer_data: Dict[str, Any]) -> Dict[str, Any]:
#         """Initiate fund transfer."""
#         response = self.client.post('/api/transfers/', data=transfer_data)
#         response.raise_for_status()
#         return response.json()

# # ==================================================
# # authentication/middleware.py - Token Validation Middleware
# from typing import Callable
# from django.http import HttpRequest, HttpResponse
# from django.utils.deprecation import MiddlewareMixin
# import logging

# from .types import AlgorithmType

# logger = logging.getLogger(__name__)

# class JWTValidationMiddleware(MiddlewareMixin):
#     """
#     Middleware to validate JWT tokens and add payload to request.
#     """
    
#     def __init__(self, get_response: Callable):
#         super().__init__(get_response)
#         self.token_manager = JWTTokenManager(AlgorithmType.RSA)
#         self.get_response = get_response
    
#     def process_request(self, request: HttpRequest) -> None:
#         """Process incoming request and validate JWT if present."""
#         # Skip validation for certain paths
#         excluded_paths = getattr(settings, 'JWT_EXCLUDE_PATHS', [
#             '/admin/', '/api/auth/login/', '/api/auth/refresh/'
#         ])
        
#         if any(request.path.startswith(path) for path in excluded_paths):
#             return None
        
#         auth_header = request.META.get('HTTP_AUTHORIZATION')
#         if not auth_header or not auth_header.startswith('Bearer '):
#             return None
        
#         token = auth_header.split(' ')[1]
        
#         try:
#             payload = self.token_manager.verify_token(token)
#             request.jwt_payload = payload
#             request.jwt_token = token
            
#             # Log successful validation for audit
#             logger.info(f"JWT validated for user {payload.username} on {request.path}")
            
#         except Exception as e:
#             logger.warning(f"JWT validation failed: {e}")
#             request.jwt_payload = None
#             request.jwt_token = None
    
#     def process_response(self, request: HttpRequest, response: HttpResponse) -> HttpResponse:
#         """Process response and add security headers."""
#         # Add security headers
#         response['X-Content-Type-Options'] = 'nosniff'
#         response['X-Frame-Options'] = 'DENY'
#         response['X-XSS-Protection'] = '1; mode=block'
        
#         return response

# # ==================================================
# # authentication/serializers.py - DRF Serializers
# from rest_framework import serializers
# from django.contrib.auth.models import User

# class LoginSerializer(serializers.Serializer):
#     """Serializer for user login."""
#     username = serializers.CharField(max_length=150)
#     password = serializers.CharField(write_only=True)
#     service = serializers.CharField(max_length=50, default='default')

# class TokenRefreshSerializer(serializers.Serializer):
#     """Serializer for token refresh."""
#     refresh_token = serializers.CharField()

# class TokenRevokeSerializer(serializers.Serializer):
#     """Serializer for token revocation."""
#     token = serializers.CharField(required=False)

# class UserInfoSerializer(serializers.ModelSerializer):
#     """Serializer for user information."""
#     permissions = serializers.ListField(read_only=True)
    
#     class Meta:
#         model = User
#         fields = ['id', 'username', 'email', 'first_name', 'last_name', 'permissions']
#         read_only_fields = ['id', 'username']

# # ==================================================
# # tests/test_authentication.py - Comprehensive Tests
# from django.test import TestCase
# from django.contrib.auth.models import User
# from unittest.mock import patch, MagicMock

# from authentication.managers.token_manager import JWTTokenManager
# from authentication.types import AlgorithmType
# from authentication.exceptions import ExpiredTokenException

# class TestJWTTokenManager(TestCase):
#     """Test JWT token management functionality."""
    
#     def setUp(self):
#         self.user = User.objects.create_user(
#             username='testuser',
#             email='test@example.com',
#             password='testpass123'
#         )
#         self.token_manager = JWTTokenManager(AlgorithmType.RSA)
    
#     @patch('authentication.crypto.key_manager.CryptoKeyManager._load_private_key')
#     @patch('authentication.crypto.key_manager.CryptoKeyManager._load_public_key')
#     def test_create_access_token(self, mock_public_key, mock_private_key):
#         """Test access token creation."""
#         # Mock the key loading
#         mock_private_key.return_value = MagicMock()
#         mock_public_key.return_value = MagicMock()
        
#         token = self.token_manager.create_access_token(
#             user=self.user,
#             service='test-service',
#             permissions=['read', 'write']
#         )
        
#         self.assertIsInstance(token, str)
#         self.assertTrue(len(token) > 0)
    
#     def test_token_blacklisting(self):
#         """Test token blacklisting functionality."""
#         # Create a mock token
#         test_token = "test.jwt.token"
        
#         # Test blacklisting
#         self.token_manager.blacklist_token(test_token)
        
#         # Test if token is blacklisted (this would need proper implementation)
#         # self.assertTrue(self.token_manager.is_token_blacklisted(test_token))

# class TestCryptoKeyManager(TestCase):
#     """Test cryptographic key management."""
    
#     def test_unsupported_algorithm(self):
#         """Test handling of unsupported algorithms."""
#         with self.assertRaises(Exception):
#             CryptoKeyManager("UNSUPPORTED_ALGO")
    
#     @patch('pathlib.Path.exists')
#     def test_key_file_not_found(self, mock_exists):
#         """Test handling when key files don't exist."""
#         mock_exists.return_value = False
        
#         key_manager = CryptoKeyManager(AlgorithmType.RSA)
        
#         with self.assertRaises(Exception):
#             _ = key_manager.private_key

# # # ==================================================
# # # docker-compose.yml - Development Environment
# # version: '3.8'

# # services:
# #   auth-service:
# #     build: ./auth_service
# #     ports:
# #       - "8000:8000"
# #     environment:
# #       - DEBUG=True
# #       - REDIS_URL=redis://redis:6379/1
# #     volumes:
# #       - ./keys:/app/keys
# #     depends_on:
# #       - redis
# #       - postgres
    
# #   bank-service:
# #     build: ./bank_service
# #     ports:
# #       - "8001:8000"
# #     environment:
# #       - DEBUG=True
# #       - AUTH_SERVICE_URL=http://auth-service:8000
# #       - REDIS_URL=redis://redis:6379/2
# #     volumes:
# #       - ./keys:/app/keys
# #     depends_on:
# #       - redis
# #       - postgres
# #       - auth-service
  
# #   redis:
# #     image: redis:7-alpine
# #     ports:
# #       - "6379:6379"
# #     volumes:
# #       - redis_data:/data
  
# #   postgres:
# #     image: postgres:15-alpine
# #     environment:
# #       - POSTGRES_DB=microservices
# #       - POSTGRES_USER=postgres
# #       - POSTGRES_PASSWORD=postgres
# #     ports:
# #       - "5432:5432"
# #     volumes:
# #       - postgres_data:/var/lib/postgresql/data

# # volumes:
# #   redis_data:
# #   postgres_data:

# # # ==================================================
# # # requirements.txt - Python Dependencies
# # Django==4.2.7
# # djangorestframework==3.14.0
# # djangorestframework-simplejwt==5.3.0
# # django-redis==5.4.0
# # django-cors-headers==4.3.1
# # PyJWT[crypto]==2.8.0
# # cryptography==41.0.7
# # redis==5.0.1
# # psycopg2-binary==2.9.9
# # celery==5.3.4
# # gunicorn==21.2.0
# # python-decouple==3.8

# # # Development dependencies
# # pytest==7.4.3
# # pytest-django==4.7.0
# # coverage==7.3.2
# # black==23.11.0
# # flake8==6.1.0
# # mypy==1.7.1