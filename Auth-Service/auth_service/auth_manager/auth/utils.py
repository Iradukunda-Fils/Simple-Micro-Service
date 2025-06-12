import jwt
import requests
import logging
from django.core.cache import cache
from django.utils import timezone

from typing import Optional, Tuple, Dict, Any
from django.conf import settings
from datetime import datetime
from .exceptions import InvalidTokenType

# mixins.py

logger = logging.getLogger(__name__)


class JWTTokenValidator:
    """
    Professional JWT token validation utility with comprehensive error handling
    and caching for optimal performance.
    """
    
    CACHE_PREFIX = 'jwt_token_cache'
    BLACKLIST_PREFIX = 'jwt_blacklist'
    
    @classmethod
    def decode_token(cls, token: str, verify_exp: bool = True, token_type = "access") -> Tuple | Dict[str, Any] | str:
        """
        Decode JWT token with comprehensive error handling.
        
        Returns:
            Tuple of (payload, error_message)
        """
        if not token or not isinstance(token, str):
            return None, "Invalid token format"
        
        # Check if token is blacklisted
        if cls._is_token_blacklisted(token):
            return None, "Token has been revoked"
        
        # Check cache first for performance
        cache_key = f"{cls.CACHE_PREFIX}:{hash(token)}"
        cached_payload = cache.get(cache_key)
        
        if cached_payload and verify_exp:
            # Verify expiration from cache
            exp_timestamp = cached_payload.get('exp')
            if exp_timestamp and datetime.fromtimestamp(exp_timestamp) > timezone.now():
                return cached_payload, None
        
        try:
            payload = jwt.decode(
                token,
                settings.PUBLIC_KEY,
                algorithms=[settings.SIMPLE_JWT.get('ALGORITHM', 'RS256')],
                options={'verify_exp': verify_exp}
            )
            
            if payload["token_type"] != token_type:
                raise InvalidTokenType("the token type not match.")
            
            # Cache valid payload for 5 minutes
            if verify_exp:
                cache.set(cache_key, payload, 300)
            
            return payload, None
                
        except jwt.ExpiredSignatureError:
            # Remove from cache if expired
            cache.delete(cache_key)
            return None, "Token has expired"
        
        except InvalidTokenType as e:
            logger.warning(f"Invalid token type: {str(e)}")
            return None, (f"Invalid token type: {e}") 
        
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {str(e)}")
            return None, "Invalid token"
        
        except Exception as e:
            logger.error(f"Unexpected error decoding JWT: {str(e)}")
            return None, "Token validation failed"
    
    @classmethod
    def _is_token_blacklisted(cls, token: str) -> bool:
        """Check if token is in blacklist cache."""
        blacklist_key = f"{cls.BLACKLIST_PREFIX}:{hash(token)}"
        return cache.get(blacklist_key, False)
    
    @classmethod
    def blacklist_token(cls, token: str, expiry_seconds: int = 1200):
        """Add token to blacklist."""
        blacklist_key = f"{cls.BLACKLIST_PREFIX}:{hash(token)}"
        cache.set(blacklist_key, True, expiry_seconds)


class JWTTokenRefreshService:
    """
    Professional token refresh service with retry logic and comprehensive error handling.
    """
    
    MAX_RETRIES = 3
    RETRY_DELAY = 1  # seconds
    
    @classmethod
    def refresh_access_token(cls, refresh_token: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Attempt to refresh access token using refresh token.
        
        Returns:
            Tuple of (new_access_token, new_refresh_token, error_message)
        """
        if not refresh_token:
            return None, None, "Refresh token not provided"
        
        # Validate refresh token first
        payload, error = JWTTokenValidator.decode_token(refresh_token, verify_exp=True)
        if error:
            return None, None, f"Invalid refresh token: {error}"
        
        # Ensure it's actually a refresh token
        token_type = payload.get('token_type', 'access')
        if token_type != 'refresh':
            return None, None, "Invalid token type for refresh operation"
        
        auth_url = getattr(settings, 'AUTH_URL', '')
        if not auth_url:
            logger.error("AUTH_URL not configured in settings")
            return None, None, "Authentication service not configured"
        
        refresh_endpoint = f"{auth_url.rstrip(' /')}/token/refresh/"
        
        for attempt in range(cls.MAX_RETRIES):
            try:
                response = requests.post(
                    refresh_endpoint,
                    json={'refresh': refresh_token},
                    headers={
                        'Content-Type': 'application/json',
                        'User-Agent': 'Django-JWT-Middleware/1.0'
                    },
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    new_access_token = data.get('access')
                    new_refresh_token = data.get('refresh', refresh_token)  # Some APIs don't return new refresh
                    
                    if new_access_token:
                        logger.info(f"Successfully refreshed token for user on attempt {attempt + 1}")
                        return new_access_token, new_refresh_token, None
                    else:
                        return None, None, "No access token in refresh response"
                
                elif response.status_code == 401:
                    return None, None, "Refresh token has expired or is invalid"
                
                elif response.status_code >= 500 and attempt < cls.MAX_RETRIES - 1:
                    # Retry on server errors
                    logger.warning(f"Server error on token refresh attempt {attempt + 1}: {response.status_code}")
                    continue
                
                else:
                    logger.error(f"Token refresh failed with status {response.status_code}: {response.text}")
                    return None, None, f"Token refresh failed: {response.status_code}"
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Token refresh timeout on attempt {attempt + 1}")
                if attempt == cls.MAX_RETRIES - 1:
                    return None, None, "Token refresh service timeout"
            
            except requests.exceptions.RequestException as e:
                logger.error(f"Network error during token refresh: {str(e)}")
                if attempt == cls.MAX_RETRIES - 1:
                    return None, None, "Network error during token refresh"
        
        return None, None, "Token refresh failed after all retry attempts"



# Settings configuration example
# Add to your Django settings.py:
"""
# JWT Configuration
SIMPLE_JWT = {
    'ALGORITHM': 'RS256',
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
}

# Your public key for JWT verification
PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
Your RSA public key here
-----END PUBLIC KEY-----'''

# Authentication service URL
AUTH_URL = 'https://your-auth-service.com/api/auth'

# JWT Token lifetimes in seconds
JWT_ACCESS_TOKEN_LIFETIME = 3600  # 1 hour
JWT_REFRESH_TOKEN_LIFETIME = 604800  # 7 days

# Caching configuration for optimal performance
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'jwt_auth.log',
        },
    },
    'loggers': {
        'jwt_auth': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
"""