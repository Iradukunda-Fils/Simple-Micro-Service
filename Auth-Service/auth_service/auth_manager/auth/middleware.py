from django.contrib.auth import authenticate
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpRequest, HttpResponse
from django.contrib.auth.models import AnonymousUser
from typing import Optional

import logging

logger = logging.getLogger(__name__)

class JWTAuthenticationMiddleware(MiddlewareMixin):
    """
    Professional JWT Authentication Middleware with separation of concerns.
    Handles token validation and user authentication without automatic refresh.
    """
    
    EXCLUDED_PATHS = [
        '/health/',
        '/admin/login/',
        '/api/auth/login/',
        '/api/auth/register/',
        '/static/',
        '/media/',
    ]
    
    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        """
        Process incoming request and authenticate user if valid JWT token is present.
        Does not perform automatic token refresh - that's handled by the mixin.
        """
        # Skip authentication for excluded paths
        if self._should_skip_authentication(request):
            return None
        
        # Set default anonymous user
        request.user = AnonymousUser()
        
        # Extract token from request
        token = self._extract_token(request)
        
        if not token:
            # No token provided - user remains anonymous
            return None
        
        # Validate token and authenticate user
        user = authenticate(request, token)
        if user:
            request.user = user
            # Add token info to request for potential use by views
            request.jwt_token = token
            
        logger.warning(f"Invalid JWT on path {request.path}")
        return None
    
    def _should_skip_authentication(self, request: HttpRequest) -> bool:
        """Check if authentication should be skipped for this request."""
        return any(request.path_info.startswith(excluded) for excluded in self.EXCLUDED_PATHS)
    
    def _extract_token(self, request: HttpRequest) -> Optional[str]:
        """
        Extract JWT token from Authorization header or cookies.
        Prioritizes Authorization header over cookies.
        """
        # Check Authorization header first
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            return auth_header.split(' ', 1)[1].strip()
        
        # Fallback to cookies
        return request.COOKIES.get('access_token', ).strip() if request.COOKIES.get('access_token', None) is not None else   None
    
    


