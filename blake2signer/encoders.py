"""Encoders: classes that implement the EncoderInterface."""

import typing

from .interfaces import EncoderInterface
from .utils import b64decode
from .utils import b64encode


class B64URLEncoder(EncoderInterface):
    """Base64 URL safe encoder."""

    def encode(self, data: typing.AnyStr) -> bytes:
        """Encode given data to base64 URL safe without padding."""
        return b64encode(data)

    def decode(self, data: typing.AnyStr) -> bytes:
        """Decode given encoded data from base64 URL safe without padding."""
        return b64decode(data)
