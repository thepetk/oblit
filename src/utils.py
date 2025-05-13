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
