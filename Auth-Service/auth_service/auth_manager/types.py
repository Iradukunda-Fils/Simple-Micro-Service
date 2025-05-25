from typing import Protocol, Dict, Any, Optional, Union, Literal
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

class AlgorithmType(str, Enum):
    RSA = "RSA"
    ECDSA = "ECDSA"
    EdDSA = "EdDSA"

class JWTAlgorithm(str, Enum):
    RS256 = "RS256"
    ES256 = "ES256"
    EdDSA = "EdDSA"

@dataclass(frozen=True)
class TokenPayload:
    user_id: int
    username: str
    email: str
    service: str
    permissions: list[str]
    iat: int
    exp: int
    aud: list[str]
    iss: str
    jti: str

@dataclass(frozen=True)
class KeyConfig:
    algorithm_type: AlgorithmType
    jwt_algorithm: JWTAlgorithm
    private_key_path: str
    public_key_path: str

class CryptoKeyManagerProtocol(Protocol):
    def load_private_key(self, key_path: str) -> Any: ...
    def load_public_key(self, key_path: str) -> Any: ...
    def sign_token(self, payload: Dict[str, Any]) -> str: ...
    def verify_token(self, token: str) -> Dict[str, Any]: ...