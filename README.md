# oblit

oblit (Oblivious Transfer) is an oblivious transfer protocol CLI tool written in python. The project has been developed in the context of the Privacy Protection course of Rovira i Virgili University.

## Background

Oblivious Transfer (OT) is a cryptographic primitive that ensures secure communication and data-exchange between two parties. A sender is able to transfer one of many pieces of information to a receiver, without knowing which piece was received, while ensuring the receiver learns nothing about the other pieces. This project showcases an Oblivious Transfer protocol approach called `oblit`.

`oblit` uses a hybrid scheme for encryption. First, it utilizes RSA for the choice of the message (exchange of public keys and the choice of public key). Then, it uses AES-GCM to encrypt the messages sent from sender to the receiver.

## Installation

The project has a straightforward [Makefile](./Makefile) which aims to make its usage and installation easier. That said, all you have to do is:

```bash
make install
```

## Usage

`oblit` currently supports two types of commands:

- `serve`: serves the messages that the sender wants to share over a socket connection.

```
oblit serve --help
Usage: oblit serve [OPTIONS] MESSAGES

  open's a socket connection to share the messages with the receiver

Options:
  -h, --host TEXT     Server host
  -p, --port INTEGER  Server port
  --help              Show this message and exit.
```

- `receive`: connects to the same socket, specifies the receiver's choice and then decrypt the given data.

```
oblit receive --help
Usage: oblit receive [OPTIONS]

  connect to sender's socket and receive the chosen message

Options:
  -h, --host TEXT     Server host
  -p, --port INTEGER  Server port
  --help              Show this message and exit.
```

Some examples are:

- Serve messages `message1`, `message2` on `localhost` at port `1000`:

```bash
oblit serve -h localhost -p 1000 "message1;message2"
```

- Receive messages from an already existing socket connection on `localhost` at port `1000`:

```bash
oblit receive -h localhost -p 1000
```

## Contribution

The project is under construction, however if you have any questions or suggestions feel free either to create an issue or a pull request.
