import jwt
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from django.conf import settings
from django.core.cache import cache

from ..types import AlgorithmType, JWTAlgorithm, KeyConfig
from ..exceptions import KeyLoadException, UnsupportedAlgorithmException

logger = logging.getLogger(__name__)

class CryptoKeyManager:
    """
    Manages cryptographic keys for JWT signing and verification.
    Supports RSA, ECDSA, and EdDSA algorithms with caching optimization.
    """
    
    def __init__(self, algorithm_type: AlgorithmType):
        self.algorithm_type = algorithm_type
        self.config = self._get_algorithm_config()
        self._private_key: Optional[Any] = None
        self._public_key: Optional[Any] = None
        
    def _get_algorithm_config(self) -> KeyConfig:
        """Get configuration for the specified algorithm type."""
        algo_configs = getattr(settings, 'CRYPTO_ALGORITHMS', {})
        
        if self.algorithm_type not in algo_configs:
            raise UnsupportedAlgorithmException(
                f"Algorithm {self.algorithm_type} is not supported"
            )
            
        config = algo_configs[self.algorithm_type]
        return KeyConfig(
            algorithm_type=self.algorithm_type,
            jwt_algorithm=JWTAlgorithm(config['sign']),
            private_key_path=str(settings.BASE_DIR / 'keys' / config['private_key_file']),
            public_key_path=str(settings.BASE_DIR / 'keys' / config['public_key_file'])
        )
    
    @property
    def private_key(self) -> Any:
        """Lazy load and cache private key."""
        if self._private_key is None:
            cache_key = f"private_key_{self.algorithm_type}"
            self._private_key = cache.get(cache_key)
            
            if self._private_key is None:
                self._private_key = self._load_private_key()
                cache.set(cache_key, self._private_key, timeout=3600)  # 1 hour
                
        return self._private_key
    
    @property 
    def public_key(self) -> Any:
        """Lazy load and cache public key."""
        if self._public_key is None:
            cache_key = f"public_key_{self.algorithm_type}"
            self._public_key = cache.get(cache_key)
            
            if self._public_key is None:
                self._public_key = self._load_public_key()
                cache.set(cache_key, self._public_key, timeout=3600)  # 1 hour
                
        return self._public_key
    
    def _load_private_key(self) -> Any:
        """Load private key based on algorithm type."""
        try:
            key_path = Path(self.config.private_key_path)
            if not key_path.exists():
                raise KeyLoadException(f"Private key file not found: {key_path}")
                
            with open(key_path, 'rb') as key_file:
                key_data = key_file.read()
                
            return serialization.load_pem_private_key(
                key_data, 
                password=None
            )
            
        except Exception as e:
            logger.error(f"Failed to load private key for {self.algorithm_type}: {e}")
            raise KeyLoadException(f"Could not load private key: {e}")
    
    def _load_public_key(self) -> Any:
        """Load public key based on algorithm type."""
        try:
            key_path = Path(self.config.public_key_path)
            if not key_path.exists():
                raise KeyLoadException(f"Public key file not found: {key_path}")
                
            with open(key_path, 'rb') as key_file:
                key_data = key_file.read()
                
            return serialization.load_pem_public_key(key_data)
            
        except Exception as e:
            logger.error(f"Failed to load public key for {self.algorithm_type}: {e}")
            raise KeyLoadException(f"Could not load public key: {e}")
    
    def sign_token(self, payload: Dict[str, Any]) -> str:
        """Sign JWT token with private key."""
        try:
            return jwt.encode(
                payload=payload,
                key=self.private_key,
                algorithm=self.config.jwt_algorithm.value
            )
        except Exception as e:
            logger.error(f"Token signing failed: {e}")
            raise InvalidTokenException("Failed to sign token")
    
    def verify_token(self, token: str, audience: Optional[list[str]] = None) -> Dict[str, Any]:
        """Verify JWT token with public key."""
        try:
            return jwt.decode(
                jwt=token,
                key=self.public_key,
                algorithms=[self.config.jwt_algorithm.value],
                audience=audience,
                issuer=getattr(settings, 'JWT_SETTINGS', {}).get('ISSUER')
            )
        except jwt.ExpiredSignatureError:
            raise ExpiredTokenException("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token verification failed: {e}")
            raise InvalidTokenException("Invalid token")

