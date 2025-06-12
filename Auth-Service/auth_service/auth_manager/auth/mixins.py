from django.contrib.auth.mixins import AccessMixin
from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.auth import authenticate
from django.conf import settings
from django.http import HttpRequest, JsonResponse
from .utils import JWTTokenRefreshService
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class BaseJWTAccessMixin(AccessMixin):
    """
    Base JWT Authentication Mixin that extends AccessMixin.
    Handles JWT token refresh and provides comprehensive authentication logic.
    """
    
    # Override LoginRequiredMixin settings
    raise_exception = False
    permission_denied_message = "Authentication required"
    
    def dispatch(self, request, *args, **kwargs):
        """
        Override dispatch to handle JWT authentication with automatic token refresh.
        """
        # Check if user is already authenticated
        if request.user.is_authenticated:
            response = super().dispatch(request, *args, **kwargs)
            return self.finalize_response(request, response)
        
        # Attempt token refresh if refresh token is available
        refresh_token = self._get_refresh_token(request)
        
        if refresh_token is not None:
            success = self._attempt_token_refresh(request, refresh_token)
            if success:
                # Re-authenticate with new token
                self._reauthenticate_user(request)
                if request.user.is_authenticated:
                    response = super().dispatch(request, *args, **kwargs)
                    return self.finalize_response(request, response)
        
        # Handle authentication failure
        return self._handle_no_permission(request)
    
    def _get_refresh_token(self, request: HttpRequest) -> Optional[str]:
        """Extract refresh token from secure HTTP-only cookie."""
        return request.COOKIES.get('refresh_token', None)
    
    def _attempt_token_refresh(self, request: HttpRequest, refresh_token: str) -> bool:
        """
        Attempt to refresh the access token using the refresh token.
        
        Returns:
            bool: True if refresh was successful, False otherwise
        """
        new_access_token, new_refresh_token, error = JWTTokenRefreshService.refresh_access_token(refresh_token)
        
        if error:
            logger.info(f"Token refresh failed: {error}")
            # Clear invalid refresh token
            self._clear_auth_cookies(request)
            return False
        
        if new_access_token:
            # Store new tokens for the response
            request._jwt_new_access_token = new_access_token
            request._jwt_new_refresh_token = new_refresh_token
            
            # Update request headers for immediate use
            request.META['HTTP_AUTHORIZATION'] = f'Bearer {new_access_token}'
            
            logger.info("Successfully refreshed JWT token")
            return True
        
        return False
    
    def _reauthenticate_user(self, request: HttpRequest):
        """Re-run authentication middleware logic with new token."""
        token = request.META.get('HTTP_AUTHORIZATION', '').replace('Bearer ', '').strip()
        if token:
            user = authenticate(request, token)
            if user:
                request.user = user
                request.jwt_token = token
    
    def _clear_auth_cookies(self, request: HttpRequest):
        """Mark authentication cookies for deletion."""
        request._clear_auth_cookies = True
    
    def _handle_no_permission(self, request: HttpRequest):
        """
        Handle cases where authentication is required but user is not authenticated.
        """
        if request.headers.get('Accept', '').startswith('application/json') or request.path.startswith('/api/'):
            # Return JSON response for API requests
            return JsonResponse({
                'error': 'Authentication required',
                'code': 'AUTHENTICATION_REQUIRED',
                'message': 'Valid authentication credentials must be provided'
            }, status=401)
        
        # For web requests, redirect to login
        messages.error(request, 'Please log in to access this page.')
        return redirect(f"{self.get_login_url()}?next={request.get_full_path()}")
    
    def finalize_response(self, request, response, *args, **kwargs):
        """
        Override to set new JWT tokens in cookies if they were refreshed.
        """
        
        from types import FunctionType
        
        base_finalize = getattr(super(), 'finalize_response', None)

        # If using DRF, call DRF's version
        if isinstance(base_finalize, FunctionType):
            response = base_finalize(request, response, *args, **kwargs)

        
        # Set new tokens in cookies if they were refreshed
        if hasattr(request, '_jwt_new_access_token'):
            response.set_cookie(
                'access_token',
                request._jwt_new_access_token,
                max_age=getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME', 3600),
                httponly=True,
                secure=request.is_secure(),
                samesite='Lax'
            )
        
        if hasattr(request, '_jwt_new_refresh_token'):
            response.set_cookie(
                'refresh_token',
                request._jwt_new_refresh_token,
                max_age=getattr(settings, 'JWT_REFRESH_TOKEN_LIFETIME', 86400 * 7),
                httponly=True,
                secure=request.is_secure(),
                samesite='Lax'
            )
        
        # Clear auth cookies if requested
        if hasattr(request, '_clear_auth_cookies') and request._clear_auth_cookies is True:
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
        
        return response
    
    
class JWTLoginRequiredMixin(BaseJWTAccessMixin):
    ...