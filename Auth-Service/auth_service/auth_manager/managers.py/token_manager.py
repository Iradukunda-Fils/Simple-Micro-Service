# ==================================================
# authentication/managers/token_manager.py - Token Management
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from django.contrib.auth.models import User
from django.core.cache import cache
from django.conf import settings

from ..crypto.key_manager import CryptoKeyManager
from ..types import AlgorithmType, TokenPayload
from ..exceptions import InvalidTokenException

class JWTTokenManager:
    """
    Manages JWT token creation, validation, and blacklisting.
    Implements token rotation and security best practices.
    """
    
    def __init__(self, algorithm_type: AlgorithmType = AlgorithmType.RSA):
        self.key_manager = CryptoKeyManager(algorithm_type)
        self.jwt_settings = getattr(settings, 'JWT_SETTINGS', {})
    
    def create_access_token(self, user: User, service: str, permissions: list[str]) -> str:
        """Create a new access token for the user."""
        now = datetime.now(timezone.utc)
        exp = now + self.jwt_settings.get('ACCESS_TOKEN_LIFETIME')
        
        payload = {
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'service': service,
            'permissions': permissions,
            'iat': int(now.timestamp()),
            'exp': int(exp.timestamp()),
            'aud': self.jwt_settings.get('AUDIENCE', []),
            'iss': self.jwt_settings.get('ISSUER'),
            'jti': str(uuid.uuid4()),
            'token_type': 'access'
        }
        
        return self.key_manager.sign_token(payload)
    
    def create_refresh_token(self, user: User, service: str) -> str:
        """Create a new refresh token for the user."""
        now = datetime.now(timezone.utc)
        exp = now + self.jwt_settings.get('REFRESH_TOKEN_LIFETIME')
        
        payload = {
            'user_id': user.id,
            'username': user.username,
            'service': service,
            'iat': int(now.timestamp()),
            'exp': int(exp.timestamp()),
            'aud': self.jwt_settings.get('AUDIENCE', []),
            'iss': self.jwt_settings.get('ISSUER'),
            'jti': str(uuid.uuid4()),
            'token_type': 'refresh'
        }
        
        return self.key_manager.sign_token(payload)
    
    def verify_token(self, token: str) -> TokenPayload:
        """Verify and decode JWT token."""
        # Check if token is blacklisted
        if self.is_token_blacklisted(token):
            raise InvalidTokenException("Token has been revoked")
        
        payload = self.key_manager.verify_token(
            token=token,
            audience=self.jwt_settings.get('AUDIENCE')
        )
        
        return TokenPayload(
            user_id=payload['user_id'],
            username=payload['username'],
            email=payload['email'],
            service=payload['service'],
            permissions=payload.get('permissions', []),
            iat=payload['iat'],
            exp=payload['exp'],
            aud=payload['aud'],
            iss=payload['iss'],
            jti=payload['jti']
        )
    
    def blacklist_token(self, token: str) -> None:
        """Add token to blacklist."""
        try:
            payload = self.key_manager.verify_token(token)
            jti = payload.get('jti')
            exp = payload.get('exp')
            
            if jti and exp:
                # Calculate TTL based on token expiration
                ttl = exp - int(datetime.now(timezone.utc).timestamp())
                if ttl > 0:
                    cache.set(f"blacklist_{jti}", True, timeout=ttl)
                    
        except Exception:
            # If token is invalid, we don't need to blacklist it
            pass
    
    def is_token_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted."""
        try:
            payload = self.key_manager.verify_token(token)
            jti = payload.get('jti')
            return bool(cache.get(f"blacklist_{jti}"))
        except Exception:
            return False
    
    def refresh_access_token(self, refresh_token: str) -> Dict[str, str]:
        """Create new access token using refresh token."""
        payload = self.verify_token(refresh_token)
        
        if payload.token_type != 'refresh':
            raise InvalidTokenException("Invalid refresh token")
        
        # Get user
        try:
            user = User.objects.get(id=payload.user_id)
        except User.DoesNotExist:
            raise InvalidTokenException("User not found")
        
        # Create new tokens
        new_access_token = self.create_access_token(
            user=user,
            service=payload.service,
            permissions=payload.permissions
        )
        
        new_refresh_token = None
        if self.jwt_settings.get('ROTATE_REFRESH_TOKENS'):
            new_refresh_token = self.create_refresh_token(user, payload.service)
            
            if self.jwt_settings.get('BLACKLIST_AFTER_ROTATION'):
                self.blacklist_token(refresh_token)
        
        result = {'access_token': new_access_token}
        if new_refresh_token:
            result['refresh_token'] = new_refresh_token
            
        return result
