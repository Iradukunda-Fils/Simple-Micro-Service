import secrets
from django.db import models
from django.contrib.auth import get_user_model

# Get the user model defined in AUTH_USER_MODEL
User = get_user_model()

type Model = models.Model

def get_secure_unique_id(
    model: Model, /, 
    max_digits: int = 8, *,
    field_name: str = None
) -> int:
    """
    Generate a secure and unique numeric ID for a model field (e.g., account number).

    Args:
        model (Type[models.Model]): The model class to check uniqueness against.
        max_digits (int): Length of the generated ID (number of digits).
        field_name (str): The model field name where the ID will be stored (must be provided).

    Returns:
        int: A unique, secure random integer ID.
    
    Raises:
        ValueError: If field_name is not provided.
    """
    if field_name is None:
        raise ValueError("You must provide a 'field_name' to check for uniqueness.")

    while True:
        # Generate a secure random number of the given digit length
        secure_id = int(''.join(secrets.choice('0123456789') for _ in range(max_digits)))
        
        # Check for uniqueness in the specified model field
        if not model.objects.filter(**{field_name: secure_id}).exists():
            return secure_id
