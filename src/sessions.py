from typing import Any
import os
import secrets
import hashlib
from .constants import (
    DEFAULT_HKDF_SALT,
    DEFAULT_HKDF_SYMMETRIC_KEY_LENGTH,
    DEFAULT_ECC_CURVE,
    DEFAULT_NONCE_SIZE,
    DEFAULT_RANDOM_SECRET_KEY_LENGTH,
)

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class BaseSession:
    """
    the base session class provides all tools required for the sender
    and the receiver sessions. Mostly focuses on cryptographic, ensuring
    that both approaches are operating with the same cryptographic flow.
    """

    def load_private_key(self, data: "str") -> "ec.EllipticCurvePrivateKey":
        """
        loads an elliptic curve private key from a given pem string
        """
        return serialization.load_pem_private_key(data.encode(), password=None)

    def load_public_key(self, data: "str") -> "ec.EllipticCurvePublicKey":
        """
        loads an elliptic curve private key from a given pem string
        """
        return serialization.load_pem_public_key(data.encode())

    def generate_private_key(
        self, curve=DEFAULT_ECC_CURVE
    ) -> "ec.EllipticCurvePrivateKey":
        """
        generates an eliptic curve private key for a give curve type.
        """
        return ec.generate_private_key(curve=curve)

    def derive_key(
        self,
        shared_key: "bytes",
        key_length: "int" = DEFAULT_HKDF_SYMMETRIC_KEY_LENGTH,
        key_salt: "bytes" = DEFAULT_HKDF_SALT,
    ) -> "bytes":
        """
        derives a symmetric key using HKDF
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=key_salt,
        )
        return hkdf.derive(shared_key)

    def encrypt(
        self, key: "bytes", plaintext: "bytes", nonce_size: "int" = DEFAULT_NONCE_SIZE
    ) -> "dict[str, Any]":
        """
        encrypts a given plaintext using AES-GCM and a given key
        """
        aes_gcm = AESGCM(key)
        nonce = os.urandom(nonce_size)
        ciphertext: "bytes" = aes_gcm.encrypt(nonce, plaintext)

        return {
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
        }

    def decrypt(
        self,
        key: "bytes",
        encrypted_data: "dict[str, Any]",
    ) -> "bytes":
        """
        decrypts a given AES-GCM ciphertext and key
        """
        aesgcm = AESGCM(key)
        nonce = bytes.fromhex(encrypted_data["nonce"])
        ciphertext = bytes.fromhex(encrypted_data["ciphertext"])

        return aesgcm.decrypt(nonce, ciphertext)

    def key_exchange(
        self,
        private_key: "ec.EllipticCurvePrivateKey",
        public_key: "ec.EllipticCurvePublicKey",
    ) -> "bytes":
        """
        performs key exchange using ECDH
        """
        return private_key.exchange(ec.ECDH(), public_key)


class ReceiverSession(BaseSession):
    """
    responsible to handle the receiver's session, fulfilling
    the OT protocol.

    The mechanism behind the scenes that binds the receiver
    to their choice is the choice digest which is share with
    the sender. The digest is the result of the sha256 function
    using a universally random secret key
    """

    def __init__(
        self, choice: "int", secret_key_len=DEFAULT_RANDOM_SECRET_KEY_LENGTH
    ) -> "None":
        self.choice = int(choice)
        self.receiver_key = self.generate_private_key()
        self.secret_key = secrets.token_bytes(secret_key_len)
        self.choice_sha = hashlib.sha256(
            self.secret_key + bytes([self.choice])
        ).digest()
        self.public_key_bytes = self.receiver_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _get_r0_r1(self, encrypted_data: "dict[str, Any]") -> "tuple[bytes, bytes]":
        """
        retrieve the random values used during encryption
        """

        return (
            bytes.fromhex(encrypted_data["r0"]),
            bytes.fromhex(encrypted_data["r1"]),
        )

    def get_public_data(self) -> "dict[str, str]":
        """
        returns pub key and the choice digest
        """
        return {
            "public_key": self.public_key_bytes.decode(),
            "choice_commitment": self.choice_sha.hex(),
        }

    def get_salt(self, r: "str") -> "bytes":
        return hashlib.sha256(self.choice_sha + r).digest()

    def receive_message(self, encrypted_data: "dict[str | Any]") -> "str":
        """
        decrypts the chosen message, after loading the public key,
        exchanging the shared secret and decide which message will
        be decrypted.
        """
        sender_public_key = self.load_public_key(encrypted_data["sender_public_key"])
        r0, r1 = self._get_r0_r1(encrypted_data)

        shared_secret = self.key_exchange(self.receiver_key, sender_public_key)

        r = r0 if self.choice == 0 else r1
        enc = encrypted_data["enc0"] if self.choice == 0 else encrypted_data["enc1"]
        salt = self.get_salt(r)
        key = self.derive_key(shared_key=shared_secret, key_salt=salt)

        return self.decrypt(key, enc)


class SenderSession(BaseSession):
    """
    responsible to handle the sender's session, fulfilling
    the OT protocol.

    The mechanism behind the scenes is a simple encryption
    mechanism that encrypts all messages in a specific
    way.
    """

    def __init__(self, messages: "list[str]"):
        self.messages = messages

    def get_messages_list(self, secret_key_len: "int") -> "list[tuple[str, bytes]]":
        """
        drafts a list of tuples containing the message
        and a random string.
        """
        return [
            (message, secrets.token_bytes(secret_key_len)) for message in self.messages
        ]

    def _encrypt_messages(
        self, shared_secret: "str", choice_sha: "str", secret_key_len: "int"
    ) -> "dict[str, Any]":
        res_dict = {}
        messages_list = self.get_messages_list(secret_key_len)

        for i, m in enumerate(messages_list):
            message, r = m
            salt = hashlib.sha256(choice_sha + r).digest()
            key = self.derive_key(shared_key=shared_secret, key_salt=salt)
            enc = self.encrypt(key, message)
            res_dict[f"r{i}"] = r.hex()
            res_dict[f"enc{i}"] = enc

        return res_dict

    def send(
        self,
        receiver_data: "dict[str, Any]",
        secret_key_len=DEFAULT_RANDOM_SECRET_KEY_LENGTH,
    ) -> "dict[str, Any]":
        """
        prepares all messages according to the OT protocol
        """
        receiver_public_key = self.load_public_key(
            serialization.load_pem_public_key(receiver_data["public_key"])
        )
        choice_sha = bytes.fromhex(receiver_data["choice_sha"])

        sender_key = self.generate_private_key()
        sender_public_key_bytes = sender_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        shared_secret = self.key_exchange(sender_key, receiver_public_key)

        res_dict = self._encrypt_messages(shared_secret, choice_sha, secret_key_len)
        res_dict["sender_public_key"] = sender_public_key_bytes.decode()

        return res_dict
