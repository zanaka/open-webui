class CryptoPolicyError(RuntimeError):
    """A request was refused by the encryption rules rather than by a bug.

    These carry a message meant for the person who made the request, and are
    turned into an HTTP response in main.py. Anything that swallows exceptions
    broadly should let these through.
    """


class EncryptedDataAccessDeniedError(CryptoPolicyError):
    pass
