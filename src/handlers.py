import websockets
import json
import click

from websockets import WebSocketClientProtocol

from .sessions import SenderSession, ReceiverSession
from .utils import Status
from .logger import logger


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
