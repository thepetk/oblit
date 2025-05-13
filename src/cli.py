import click

from .handlers import receiver_client_handler, sender_server


@click.group()
def cli():
    pass


@cli.command()
@click.argument("messages", required=True, type=str)
@click.option("-h", "--host", default="localhost", help="Server host")
@click.option("-p", "--port", default=8765, type=int, help="Server port")
def serve(messages: str, host: str, port: int) -> None:
    """
    open's a socket connection to share the messages with the receiver
    """
    message_list = messages.split(";")

    if len(message_list) < 2:
        click.echo(
            "Error: At least two messages must be provided, separated by semicolons"
        )
    else:
        sender_server(host, port, message_list)


@cli.command()
@click.option("-h", "--host", default="localhost", help="Server host")
@click.option("-p", "--port", default=8765, type=int, help="Server port")
def receive(host: "str", port: "int") -> "None":
    """
    connect to sender's socket and receive the chosen message
    """
    click.echo(f"Connecting to sender at {host}:{port}")
    receiver_client_handler(host, port)
