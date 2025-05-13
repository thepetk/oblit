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
                "description": {f"m{i}": f"Message {i}" for i in range(len(messages))},
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

    else:
        logger.error(f"unexpected message type: {receiver_data_msg['type']}")


async def receiver_client_handler(url: "str") -> "None":
    """
    receiver's client handler method
    """
    async with websockets.connect(url) as websocket:
        sender_msg = json.loads(await websocket.recv())

        if sender_msg["type"] == Status.SENDER_READY:
            descriptions: "dict[str, str]" = sender_msg["description"]

            click.echo("Available messages:")
            for key in descriptions.keys():
                click.echo(f"  {descriptions[key]}")

            options = list(range(len(descriptions)))
            choice = click.prompt(
                "Which message would you like to receive?",
                type=click.Choice([str(i) for i in options]),
                show_choices=True,
            )
            choice = int(choice)

            click.echo(f"You have chosen message {choice}")

            session = ReceiverSession()

            if click.confirm("Do you want to proceed with this choice?", default=True):
                await websocket.send(
                    json.dumps(
                        {
                            "type": Status.RECEIVER_CHOICE,
                            "data": session.get_public_data(choice),
                        }
                    )
                )

                logger.info(f"Sent choice commitment for message {choice}")

                encrypted_msg = json.loads(await websocket.recv())

                if encrypted_msg["type"] == Status.ENCRYPTED_MESSAGES:
                    encrypted_data = encrypted_msg["data"]
                    decrypted_data = session.receive_message(encrypted_data, choice)

                    click.echo(
                        f"\nReceived message {choice}: {decrypted_data.decode()}"
                    )

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
