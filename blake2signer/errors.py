"""Errors."""


class SignerError(Exception):
    """Base exception for errors."""


class InvalidOptionError(SignerError):
    """Invalid options error."""


class DecodeError(SignerError):
    """Decode error."""


class InvalidSignatureError(DecodeError):
    """Invalid signature error."""


class ExpiredSignatureError(InvalidSignatureError):
    """Expired signature error."""


class EncodeError(SignerError):
    """Encode error."""
