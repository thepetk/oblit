import sys
import click
import asyncio
from .handlers import receiver_client_handler, sender_server_handler
import websockets


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
