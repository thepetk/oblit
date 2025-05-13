import json
import socket
from typing import Any

from .constants import DEFAULT_BUF_SIZE, DEFAULT_LENGTH_PREF


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


def send_socket_message(
    sock: "socket.socket",
    message: "dict[str, Any]",
    length_pref=DEFAULT_LENGTH_PREF,
) -> "None":
    """
    sends a message over a socket
    """
    serialized = json.dumps(message).encode("utf-8")
    length_bytes = len(serialized).to_bytes(length_pref, byteorder="big")
    sock.sendall(length_bytes + serialized)


def receive_socket_message(
    sock: socket.socket, buf_size=DEFAULT_BUF_SIZE, length_pref=DEFAULT_LENGTH_PREF
) -> "dict[str, Any]":
    """
    receives a message from a socket using chunks
    """

    length_bytes = sock.recv(length_pref)
    if not length_bytes:
        return None

    message_length = int.from_bytes(length_bytes, byteorder="big")

    chunks = []
    bytes_received = 0

    while bytes_received < message_length:
        chunk = sock.recv(min(buf_size, message_length - bytes_received))
        if not chunk:
            return None
        chunks.append(chunk)
        bytes_received += len(chunk)

    serialized = b"".join(chunks)
    return json.loads(serialized.decode("utf-8"))
