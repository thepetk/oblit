import os
import random
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import (
    DEFAULT_KEY_BYTES_SIZE,
    DEFAULT_KEY_SIZE,
    DEFAULT_NONCE_SIZE,
)


class ReceiverSession:
    """
    responsible to handle the receiver's session.

    uses public key cryptography with arbitrary precision integers
    to implement oblivious transfer.
    """

    def __init__(
        self,
        key_size=DEFAULT_KEY_SIZE,
        symmetric_key_bytes_size=DEFAULT_KEY_BYTES_SIZE,
        nonce_size=DEFAULT_NONCE_SIZE,
    ) -> "None":
        self.key_size = key_size
        self.symmetric_key_bytes_size = symmetric_key_bytes_size
        self.symmetric_key = None
        self.chosen_message_index = None
        self.sender_public_keys = None
        self.nonce_size = nonce_size

    def _reconstruct_pk(
        self, public_keys_data: "dict[str, Any]", key_name: "str"
    ) -> "rsa.RSAPublicNumbers":
        return rsa.RSAPublicNumbers(
            e=int(public_keys_data[key_name]["e"]),
            n=int(public_keys_data[key_name]["n"]),
        )

    def set_public_keys(self, public_keys_data: "dict[str, Any]") -> "None":
        """
        stores sender's public keys
        """
        self.sender_public_keys = {
            key_name: self._reconstruct_pk(public_keys_data, key_name).public_key(
                default_backend()
            )
            for key_name in public_keys_data.keys()
        }

    def get_public_data(self, choice: "int") -> "dict[str, str]":
        """
        generates and encrypts symmetric key based on choice
        """
        self.chosen_message_index = choice

        # Note: generate large random symmetric key more than 100 digits
        self.symmetric_key = random.randrange(10**99, 10**100)

        # converts symmetric_key into bytes, then encrypt and
        # then prepare it for transfer
        chosen_pk = self.sender_public_keys[f"k{choice + 1}"]
        symmetric_key_bytes = self.symmetric_key.to_bytes(
            self.symmetric_key_bytes_size, "big"
        )
        encrypted_k_bytes = chosen_pk.encrypt(
            symmetric_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        encrypted_k_int = int.from_bytes(encrypted_k_bytes, "big")

        return {"encrypted_k": str(encrypted_k_int)}

    def decrypt_message(
        self, encrypted_data: "dict[str, Any]", choice: "int"
    ) -> "bytes":
        """
        decrypts the chosen message using RSA protocol and the
        symmetric key of the session
        """
        ciphertext = bytes.fromhex(encrypted_data[f"c{choice + 1}"])
        return self._symmetric_decrypt(ciphertext, self.symmetric_key)

    def _symmetric_decrypt(self, ciphertext: "bytes", key: "int") -> "bytes":
        """
        symmetric decryption with AES-GCM
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(str(key).encode())

        aes_key = digest.finalize()[:32]
        nonce = ciphertext[: self.nonce_size]
        encrypted_data = ciphertext[self.nonce_size :]

        aesgcm = AESGCM(aes_key)
        return aesgcm.decrypt(nonce, encrypted_data, None)


class SenderSession:
    """
    responsible to handle the sender's session, fulfilling
    the OT protocol with arbitrary precision integers.
    """

    def __init__(
        self,
        messages: "list[str]",
        key_size=DEFAULT_KEY_SIZE,
        nonce_size=DEFAULT_NONCE_SIZE,
    ) -> "None":
        self.messages = messages
        self.key_size = key_size
        self.private_keys = {
            f"k{idx + 1}": rsa.generate_private_key(
                public_exponent=65537, key_size=self.key_size, backend=default_backend()
            )
            for idx in range(len(self.messages))
        }
        self.public_keys: "dict[str, rsa.RSAPublicKey]" = {
            f"k{idx + 1}": self.private_keys[f"k{idx + 1}"].public_key()
            for idx in range(len(self.messages))
        }
        self.nonce_size = nonce_size

    def get_public_keys(self) -> "dict[str, str]":
        """
        returns all public keys in dictionary format including the
        modulus and the public exponent
        """
        return {
            key_name: {
                "n": str(self.public_keys[key_name].public_numbers().n),
                "e": str(self.public_keys[key_name].public_numbers().e),
            }
            for key_name in self.public_keys.keys()
        }

    def _decrypt_with_private_key(
        self, private_key: "rsa.RSAPrivateKey", ciphertext_int: "int"
    ) -> "int":
        """
        RSA decryption using the given private key
        """
        modulus_bits = private_key.key_size
        ciphertext_bytes = ciphertext_int.to_bytes((modulus_bits + 7) // 8, "big")
        try:
            decrypted_bytes = private_key.decrypt(
                ciphertext_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return int.from_bytes(decrypted_bytes, "big")
        # for all other messages fallback in random key
        except Exception:
            return random.randrange(10**99, 10**100)

    def encrypt_messages(self, receiver_data: "dict[str, str]") -> "dict[str, str]":
        """
        encrypts all messages based on receiver's encrypted choice
        """
        encrypted_k = int(receiver_data["encrypted_k"])
        encrypted_data: "dict[str, str]" = {}

        for idx, pk_name in enumerate(self.private_keys.keys()):
            k = self._decrypt_with_private_key(self.private_keys[pk_name], encrypted_k)
            c = self._symmetric_encrypt(self.messages[idx].encode(), k)
            encrypted_data[f"c{idx + 1}"] = c.hex()

        return encrypted_data

    def _symmetric_encrypt(self, message: "bytes", key: "int") -> "bytes":
        """
        uses AES-GCM to encrypt symmetrically
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(str(key).encode())
        aes_key = digest.finalize()[:32]
        nonce = os.urandom(self.nonce_size)
        aesgcm = AESGCM(aes_key)
        ciphertext: "bytes" = aesgcm.encrypt(nonce, message, None)
        return nonce + ciphertext
