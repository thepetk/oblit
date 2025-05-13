import sys
from typing import Any
import click
import json
import os
import secrets
import hashlib
import asyncio
import websockets
import logging
from enum import Enum

from websockets import WebSocketClientProtocol
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------- Constants ----------------------- #

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

# --------------- Logger -------------------------- #

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("dysi")

# --------------- Helper Classes ------------------ #


class Status:
    """
    status class captures the actual status of the
    communication between sender and receiver
    """

    SENDER_READY = "sender_ready"
    RECEIVER_CHOICE = "receiver_choice"
    ENCRYPTED_MESSAGES = "encrypted_messages"
    RESULT = "result"
    ERROR = "error"


# ----------------- Utils ---------------------------- #


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


# ------------- Web Socket Helpers ------------------- #


async def sender_server_handler(
    websocket: "WebSocketClientProtocol", messages: "list[str]"
) -> "None":
    """
    handles a given sender websocket with a messages list
    """
    session = SenderSession(messages=messages)
    await websocket.send(
        json.dumps(
            {
                "type": Status.SENDER_READY,
                "description": {
                    f"m{i}": f"Message {i}: {m if len(m) < 20 else m[:20] + '...'}"
                    for i, m in enumerate(messages)
                },
            }
        )
    )

    logger.info("options sent, waiting for receiver choice...")

    receiver_data_msg = json.loads(await websocket.recv())

    if receiver_data_msg["type"] == Status.RECEIVER_CHOICE:
        receiver_data = receiver_data_msg["data"]
        encrypted_data = session.send(receiver_data)

        await websocket.send(
            json.dumps(
                {
                    "type": Status.ENCRYPTED_MESSAGES,
                    "data": encrypted_data,
                }
            )
        )

        logger.info("encrypted messages sent...")

        result_msg = json.loads(await websocket.recv())
        if result_msg["type"] == Status.RESULT:
            logger.info(f"transfer completed: {result_msg['status']}")
            click.echo(f"transfer completed: {result_msg['message']}")

    else:
        logger.error(f"unexpected message type: {receiver_data_msg['type']}")


async def receiver_client_handler(url: "str", choice: "int") -> "None":
    """
    receiver's client handler method
    """
    async with websockets.connect(url) as websocket:
        session = ReceiverSession(choice=choice)
        sender_msg = json.loads(await websocket.recv())

        if sender_msg["type"] == Status.SENDER_READY:
            descriptions: "dict[str, str]" = sender_msg["description"]

            click.echo("Available messages:")
            for key in descriptions.keys():
                click.echo(f"  {descriptions[key]}")
            click.echo(f"You have chosen message {choice}")

            if click.confirm("Do you want to proceed with this choice?", default=True):
                await websocket.send(
                    json.dumps(
                        {
                            "type": Status.RECEIVER_CHOICE,
                            "data": session.get_public_data(),
                        }
                    )
                )

                logger.info(f"Sent choice commitment for message {choice}")

                # Wait for encrypted messages
                encrypted_msg = json.loads(await websocket.recv())

                if encrypted_msg["type"] == Status.ENCRYPTED_MESSAGES:
                    # Decrypt the chosen message
                    encrypted_data = encrypted_msg["data"]
                    decrypted = session.receive_message(encrypted_data)

                    # Display the decrypted message
                    click.echo(f"\nReceived message {choice}: {decrypted.decode()}")

                    # Send result back to sender
                    await websocket.send(
                        json.dumps(
                            {
                                "type": Status.RESULT,
                                "status": "success",
                                "message": f"Successfully received message {choice}",
                            }
                        )
                    )
                else:
                    logger.error(f"Unexpected message type: {encrypted_msg['type']}")
            else:
                click.echo("Transfer cancelled by user")
        else:
            logger.error(f"Unexpected message type: {sender_msg['type']}")


# -------------------- CLI --------------------------- #


@click.group()
def cli():
    pass


@cli.command()
@click.argument("messages", required=True, type=str)
@click.option("-h", "--host", default="localhost", help="WebSocket server host")
@click.option("-p", "--port", default=8765, type=int, help="WebSocket server port")
def send(messages: "str", host: "str", port: "int") -> "None":
    """
    start sender server and await for potential receivers
    """
    message_list = messages.split(";")

    if len(message_list) < 2:
        click.echo(
            "Error: At least two messages must be provided, separated by semicolons"
        )
        sys.exit(1)

    start_server = websockets.serve(
        lambda ws: sender_server_handler(ws, message_list), host, port
    )

    click.echo(f"Sender listening on ws://{host}:{port}")
    for i, msg in enumerate(message_list):
        click.echo(f"Message {i}: {msg}")

    asyncio.get_event_loop().run_until_complete(start_server)
    asyncio.get_event_loop().run_forever()


@cli.command()
@click.argument("choice", type=click.Choice(["0", "1"]))
@click.option("--url", default="ws://localhost:8765", help="WebSocket server URL")
def receive(choice, url):
    """
    connect to sender server and receive messages
    """
    click.echo(f"Connecting to sender at {url} with choice {choice}")
    asyncio.get_event_loop().run_until_complete(receiver_client_handler(url, choice))


if __name__ == "__main__":
    cli()
