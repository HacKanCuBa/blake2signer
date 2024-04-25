"""Encoders: classes that implement the EncoderInterface."""

from .interfaces import EncoderInterface
from .utils import B58_ALPHABET
from .utils import b32decode
from .utils import b32encode
from .utils import b58decode
from .utils import b58encode
from .utils import b64decode
from .utils import b64encode
from .utils import hexdecode
from .utils import hexencode


class B64URLEncoder(EncoderInterface):
    """Base64 URL-safe encoder."""

    @property
    def alphabet(self) -> bytes:
        """Return the encoder alphabet characters."""
        return b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'

    def encode(self, data: bytes) -> bytes:
        """Encode given data to base64 URL-safe without padding.

        Args:
            data: Data to encode.

        Returns:
            Encoded data.
        """
        return b64encode(data)

    def decode(self, data: bytes) -> bytes:
        """Decode given encoded data from base64 URL-safe without padding.

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


class B58Encoder(EncoderInterface):
    """Base58 encoder.

    It contains characters from a-z (except `l`), A-Z (except `I` and `O`), and numbers 1-9,
    to improve readability and reduce transcription errors.
    """

    @property
    def alphabet(self) -> bytes:
        """Return the encoder alphabet characters."""
        return B58_ALPHABET

    def encode(self, data: bytes) -> bytes:
        """Encode given data to base58.

        Args:
            data: Data to encode.

        Returns:
            Encoded data.
        """
        return b58encode(data)

    def decode(self, data: bytes) -> bytes:
        """Decode given encoded data from base58.

        Args:
            data: Data to decode.

        Returns:
            Original data.
        """
        return b58decode(data)
