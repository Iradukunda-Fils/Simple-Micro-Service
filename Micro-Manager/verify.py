import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Target directory
KEY_DIR = "micro_service/keys"
os.makedirs(KEY_DIR, exist_ok=True)

# File paths
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public.pem")

# Generate private key (2048 bits RSA)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Serialize private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),  # Optional: add password here
)

# Serialize public key
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Save private key
with open(PRIVATE_KEY_PATH, 'wb') as f:
    f.write(private_pem)
    print(f"✅ Private key saved to: {PRIVATE_KEY_PATH}")

# Save public key
with open(PUBLIC_KEY_PATH, 'wb') as f:
    f.write(public_pem)
    print(f"✅ Public key saved to: {PUBLIC_KEY_PATH}")
