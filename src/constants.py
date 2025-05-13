import os

from cryptography.hazmat.primitives.asymmetric import ec


# DEFAULT_ECC_CURVE: The curve type used for elliptic curve cryptography
DEFAULT_ECC_CURVE = ec.SECP521R1()

# DEFAULT_HKDF_SYMMETRIC_KEY_LENGTH: The length of the symmetric key
DEFAULT_HKDF_SYMMETRIC_KEY_LENGTH = 32

# DEFAULT_NONCE_SIZE: The nonce size used for AES-GCM
DEFAULT_NONCE_SIZE = 12

# DEFAULT_HKDF_SALT: Salt used for key derivation
DEFAULT_HKDF_SALT = os.getenv("DEFAULT_HKDF_SALT", "").encode("utf-8")

# DEFAULT_RANDOM_SECRET_KEY_LENGTH: length of secret key used to create
# the choice digest.
DEFAULT_RANDOM_SECRET_KEY_LENGTH = 32
