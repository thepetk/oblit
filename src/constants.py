import os

# DEFAULT_NONCE_SIZE: The nonce size used for AES-GCM
DEFAULT_NONCE_SIZE = int(os.getenv("DEFAULT_NONCE_SIZE", 12))

# DEFAULT_BUF_SIZE: The default buffer size used for socket communication
DEFAULT_BUF_SIZE = int(os.getenv("DEFAULT_BUF_SIZE", 4096))

# DEFAULT_LENGTH_PREF: The default length prefixing value
DEFAULT_LENGTH_PREF = int(os.getenv("DEFAULT_LENGTH_PREF", 4))

# DEFAULT_KEY_SIZE: The default size of key k
DEFAULT_KEY_SIZE = int(os.getenv("DEFAULT_KEY_SIZE", 3072))

# DEFAULT_KEY_BYTES_SIZE: The default bytes size of symmetric key
DEFAULT_KEY_BYTES_SIZE = int(os.getenv("DEFAULT_KEY_BYTES_SIZE", 128))
