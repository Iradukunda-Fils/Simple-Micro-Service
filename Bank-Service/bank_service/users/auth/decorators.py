from django.contrib.auth import get_user_model
from functools import wraps
from rest_framework import status
from rest_framework.response import Response

User = get_user_model()

def check_permission(role_name):
    """
    Decorator to check if the authenticated user belongs to a specific group (role).
    """
    def decorator(func_view):
        @wraps(func_view)
        def wrapper(request, *args, **kwargs):
            user = request.user

            if not user.is_authenticated:
                return Response(
                    {"detail": "Authentication required."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Check if the user belongs to the given role/group
            if user.groups.filter(name=role_name).exists():
                return func_view(request, *args, **kwargs)

            return Response(
                {"detail": f"Permission denied. Required role: '{role_name}'."},
                status=status.HTTP_403_FORBIDDEN
            )
        return wrapper
    return decorator

def check_auth(func_view):
    """
    Decorator to ensure the user is authenticated before accessing the view.
    """
    @wraps(func_view)
    def wrapper(request, *args, **kwargs):
        user = request.user

        if user.is_authenticated:
            return func_view(request, *args, **kwargs)

        return Response(
            {"detail": "Authentication required."},
            status=status.HTTP_401_UNAUTHORIZED
        )
    return wrapper

                
                