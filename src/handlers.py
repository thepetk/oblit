import socket
import threading

import click

from .logger import logger
from .sessions import ReceiverSession, SenderSession
from .utils import Status, receive_socket_message, send_socket_message


def sender_server(host: "str", port: "int", messages: "list[str]") -> "None":
    """
    the server is responsible in serving the keys and messages that
    the sender makes available and the receiver will choose to decrypt
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        # allows only one connection at a time to prevent
        # malicious attempts from receiver
        server_socket.listen(1)

        click.echo(f"Sender listening on {host}:{port}")
        for i, msg in enumerate(messages):
            click.echo(f"Message {i}: {msg}")

        while True:
            receiver_socket, addr = server_socket.accept()
            click.echo(f"Connection from {addr}")

            # serve the received connection in a thread
            thread = threading.Thread(
                target=sender_server_handler, args=(receiver_socket, messages)
            )
            thread.daemon = True
            thread.start()
            thread.join()
            break

    except KeyboardInterrupt:
        click.echo("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
    finally:
        server_socket.close()


def sender_server_handler(sock: "socket.socket", messages: "list[str]") -> "None":
    """
    handles a given socket with a messages list
    """
    session = SenderSession(messages=messages)
    try:
        # make the receiver aware of the available public keys
        send_socket_message(
            sock,
            {
                "type": Status.SENDER_READY,
                "public_keys": session.get_public_keys(),
                "message_count": len(messages),
            },
        )

        # get the key from the receiver
        receiver_data_msg = receive_socket_message(sock)
        if not receiver_data_msg or receiver_data_msg["type"] != Status.RECEIVER_CHOICE:
            logger.error("Connection closed by receiver")
            return

        # encrypt everything and send over to receiver
        if receiver_data_msg["type"] == Status.RECEIVER_CHOICE:
            receiver_data = receiver_data_msg["data"]
            encrypted_data = session.encrypt_messages(receiver_data)

            send_socket_message(
                sock, {"type": Status.ENCRYPTED_MESSAGES, "data": encrypted_data}
            )

            logger.info("Encrypted messages sent...")

            # receive confirmation
            result_msg = receive_socket_message(sock)
            if not result_msg:
                logger.error("Connection closed by receiver")
                return

            click.echo(f"Transfer completed: {result_msg['status']}")
        else:
            logger.error(f"Unexpected message type: {receiver_data_msg['type']}")

    except Exception as e:
        logger.error(f"Error in sender handler: {str(e)}")
    finally:
        sock.close()


def get_choice(options_range: "int") -> "int":
    options = list(range(options_range))
    choice = click.prompt(
        "Which message would you like to receive?",
        type=click.Choice([str(i) for i in options]),
        show_choices=True,
    )
    return int(choice)


def receiver_client_handler(host: "str", port: "int") -> "None":
    """
    client takes care of all the receiver functionality, receiving public keys,
    choosing the message, encrypting the choice, and finally decrypting result
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))

        # read available packages
        sender_msg = receive_socket_message(sock)
        if not sender_msg or sender_msg["type"] != Status.SENDER_READY:
            click.echo("Failed to receive message options from sender")
            return

        public_keys = sender_msg["public_keys"]
        message_count = sender_msg.get("message_count", 2)

        click.echo(f"Available messages: 0 to {message_count - 1}")
        choice = get_choice(message_count)

        session = ReceiverSession()
        session.set_public_keys(public_keys)

        if click.confirm("Do you want to proceed with this choice?", default=True):
            send_socket_message(
                sock,
                {
                    "type": Status.RECEIVER_CHOICE,
                    "data": session.get_public_data(choice),
                },
            )

            logger.info(f"Sent encrypted symmetric key for message {choice}")

            # get all encrypted messages
            encrypted_msg = receive_socket_message(sock)

            if not encrypted_msg or encrypted_msg["type"] != Status.ENCRYPTED_MESSAGES:
                click.echo("Failed to receive encrypted messages from sender")
                return

            encrypted_data = encrypted_msg["data"]
            decrypted_data = session.decrypt_message(encrypted_data, choice)

            click.echo(f"\nReceived message {choice}: {decrypted_data.decode()}")

            send_socket_message(
                sock,
                {
                    "type": Status.RESULT,
                    "status": "success",
                    "message": f"Successfully received message {choice}",
                },
            )

            click.echo("Transaction completed successfully")
        else:
            click.echo("Transfer cancelled by user")
    except ConnectionRefusedError:
        click.echo(f"Could not connect to sender at {host}:{port}")
    except Exception as e:
        logger.error(f"Error in receiver client: {str(e)}")
    finally:
        sock.close()
