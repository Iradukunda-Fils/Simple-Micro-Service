from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from .utils import JWTTokenValidator
from django.http import HttpRequest
from django.core.cache import cache
import logging
from typing import Optional
from datetime import datetime
from django.utils import timezone
from .exceptions import InvalidTokenType
from asgiref.sync import sync_to_async


logger = logging.getLogger(__name__)

User = get_user_model()


class JWTAuthenticationBackend(BaseBackend):
    def authenticate(self, request: HttpRequest, token: str) -> Optional[User]:
        """
        Authenticate user using JWT token.
        Returns User instance if valid, None otherwise.
        """
        payload, error = JWTTokenValidator.decode_token(token)
        
        
        
        if error:
            logger.debug(f"Token validation failed: {error}")
            return None

        try:
            user_id = payload.get('user_id')
            email = payload.get('email')
            username = payload.get('username')
            is_active = payload.get('is_active')
            
            if not user_id:
                logger.warning("JWT payload missing user_id")
                return None
            
            # Check token type is 'access'
            if (token_type := payload.get('token_type', None)) and token_type != "access":
               raise InvalidTokenType("The expected token type access, but got defferent.")

            # Attempt to get the user from cache
            cache_key = f"user_cache:{user_id}"
            user = cache.get(cache_key)

            if user == 'invalid':
                return None
            # creating of user if not exist or updating the user if exists and return the user instance
            try:
                
                if not user: 
                    # Try to update or create the user from DB
                    user, created = User.objects.update_or_create(
                        id=user_id,  # Field used to look up the object (must be unique)
                        defaults={
                            'username': username,
                            'email': email,
                            'is_active': is_active,
                        }
                    )
                    
                    # in user not active reject
                    if not user.is_active:
                       logger.warning(f"Inactive user {user_id} attempted authentication")
                       return None
                   
                    # in user created log event
                    if created:
                        logger.info(f"User {user_id} created.")
                    
                    logger.info(f"User {user_id} details updated.")
                    cache.set(f"user_cache:{user_id}", user, 600) # for 10 mins
                    return user
            
            except Exception as e:
                cache.set(cache_key, 'invalid', 300) # cache for 5 mins
                logger.error(f"Error in update_or_create for user {user_id}: {e}")
                return None
            

            # Token issued before password change
            iat = payload.get('iat')
            if iat and hasattr(user, 'last_password_change'):
                if user.last_password_change and timezone.make_aware(datetime.fromtimestamp(iat)) < user.last_password_change:
                    logger.warning(f"Token issued before password change for user {user_id}")
                    return None

            return user
        except InvalidTokenType as e:
            logger.warning(f"Invalid token type: {str(e)}")
            return None

        except Exception as e:
            logger.exception("Unexpected error during user authentication")
            return None
        
    async def aauthenticate(self, request: HttpRequest, token: str) -> Optional[User]:
        return sync_to_async(self.authenticate)(request, token)

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
        
    async def aget_user(self, user_id: int) -> Optional[User]:
        return sync_to_async(self.get_user)(user_id)
