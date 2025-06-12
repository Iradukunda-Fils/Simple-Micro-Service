from rest_framework_simplejwt.tokens import Token, BlacklistMixin, RefreshToken
from rest_framework_simplejwt.settings import api_settings
from typing import TypeVar
from datetime import timedelta, datetime
from django.contrib.auth.models import AbstractBaseUser
from django.utils.timezone import is_naive, make_aware

T = TypeVar("T", bound="Token")
Service = AbstractBaseUser

class ServiceToken(Token):
    """
    A class which validates and wraps an existing JWT or can be used to build a
    new JWT.
    """
    @classmethod
    def for_user(cls: type[T], user: Service) -> T:
        token = super().for_user(user)

        # Safely handle datetime serialization
        regist_date = getattr(user, "registered_at", None) or getattr(user, "created_at", None)

        if regist_date is not None:
            if is_naive(regist_date):
                regist_date = make_aware(regist_date)
            token["registed"] = regist_date.isoformat() # fallback (avoid crash)
            
        return token


class ServiceSlidingToken(BlacklistMixin["ServiceSlidingToken"], ServiceToken):
    token_type = "sliding_com"
    lifetime = api_settings.SLIDING_TOKEN_LIFETIME

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        if self.token is None:
            # Set sliding refresh expiration claim if new token
            self.set_exp(
                api_settings.SLIDING_TOKEN_REFRESH_EXP_CLAIM,
                from_time=self.current_time,
                lifetime=api_settings.SLIDING_TOKEN_REFRESH_LIFETIME,
            )

class ServiceAccessToken(ServiceToken):
    token_type = "access_com"
    lifetime = api_settings.ACCESS_TOKEN_LIFETIME

class ServiceRefreshToken(BlacklistMixin["ServiceRefreshToken"], ServiceToken):
    token_type = "refresh_com"
    lifetime = api_settings.REFRESH_TOKEN_LIFETIME
    no_copy_claims = (
        api_settings.TOKEN_TYPE_CLAIM,
        "exp",
        # Both of these claims are included even though they may be the same.
        # It seems possible that a third party token might have a custom or
        # namespaced JTI claim as well as a default "jti" claim.  In that case,
        # we wouldn't want to copy either one.
        api_settings.JTI_CLAIM,
        "jti",
    )
    access_token_class = ServiceAccessToken

    @property
    def access_token(self) -> ServiceAccessToken:
        """
        Returns an access token created from this refresh token.  Copies all
        claims present in this refresh token to the new access token except
        those claims listed in the `no_copy_claims` attribute.
        """
        access = self.access_token_class()

        # Use instantiation time of refresh token as relative timestamp for
        # access token "exp" claim.  This ensures that both a refresh and
        # access token expire relative to the same time if they are created as
        # a pair.
        access.set_exp(from_time=self.current_time)

        no_copy = self.no_copy_claims
        for claim, value in self.payload.items():
            if claim in no_copy:
                continue
            access[claim] = value

        return access

class ServiceUntypedToken(ServiceToken):
    token_type = "untyped_com"
    lifetime = timedelta(seconds=0)

    def verify_token_type(self) -> None:
        """
        Untyped tokens do not verify the "token_type" claim.  This is useful
        when performing general validation of a token's signature and other
        properties which do not relate to the token's intended use.
        """
        pass