from django.conf import settings

from pathlib import Path


def load_secret_key(secret_type: str, algorithm="RS256") -> bytes:
    """
    Loads and returns the content of the private or public key file in binary format.

    Args:
        secret_type (str): The type of key to load. Should be either "private" or "public".

    Returns:
        bytes: The content of the requested key file in binary format.

    Raises:
        ValueError: If secret_type is not "private" or "public".
        FileNotFoundError: If the key file does not exist.
        IOError: If there is an error reading the key file.
    """
    BASE_DIR = Path(settings.BASE_DIR)

    # Normalize the secret_type to lowercase for comparison
    secret_type = secret_type.lower()

    if secret_type == "private":
        key_path = BASE_DIR / "keys/private.pem"
    elif secret_type == "public":
        key_path = BASE_DIR / "keys/public.pem"
    else:
        raise ValueError("secret_type must be either 'private' or 'public'.")

    # Try to open the key file in binary mode and return its contents
    try:
        with open(key_path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(
            f"The {secret_type} key file does not exist at {key_path}."
        )
    except IOError as e:
        raise IOError(f"Error reading the {secret_type} key file: {e}")
