"""Encoders: classes that implement the EncoderInterface."""

from .interfaces import EncoderInterface
from .utils import b32decode
from .utils import b32encode
from .utils import b64decode
from .utils import b64encode
from .utils import hexdecode
from .utils import hexencode


class B64URLEncoder(EncoderInterface):
    """Base64 URL safe encoder."""

    @property
    def alphabet(self) -> bytes:
        """Return the encoder alphabet characters."""
        return b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'

    def encode(self, data: bytes) -> bytes:
        """Encode given data to base64 URL safe without padding.

        Args:
            data: Data to encode.

        Returns:
            Encoded data.
        """
        return b64encode(data)

    def decode(self, data: bytes) -> bytes:
        """Decode given encoded data from base64 URL safe without padding.

        Args:
            data: Data to decode.

        Returns:
            Original data.
        """
        return b64decode(data)


class B32Encoder(EncoderInterface):
    """Base32 encoder."""

    @property
    def alphabet(self) -> bytes:
        """Return the encoder alphabet characters."""
        return b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

    def encode(self, data: bytes) -> bytes:
        """Encode given data to base32 without padding.

        Args:
            data: Data to encode.

        Returns:
            Encoded data.
        """
        return b32encode(data)

    def decode(self, data: bytes) -> bytes:
        """Decode given encoded data from base32 without padding.

        Args:
            data: Data to decode.

        Returns:
            Original data.
        """
        return b32decode(data)


class HexEncoder(EncoderInterface):
    """Hexadecimal encoder."""

    @property
    def alphabet(self) -> bytes:
        """Return the encoder alphabet characters."""
        return b'ABCDEF0123456789'

    def encode(self, data: bytes) -> bytes:
        """Encode given data to hexadecimal.

        Args:
            data: Data to encode.

        Returns:
            Encoded data.
        """
        return hexencode(data)

    def decode(self, data: bytes) -> bytes:
        """Decode given encoded data from hexadecimal.

        Args:
            data: Data to decode.

        Returns:
            Original data.
        """
        return hexdecode(data)
