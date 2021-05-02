"""Interfaces: abstract classes to define serializers, encoders and compressors."""

import typing
from abc import ABC
from abc import abstractmethod


class SerializerInterface(ABC):
    """Serializer interface.

    Implement your own serializer inheriting from this class.
    """

    @abstractmethod
    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Serialize given data.

        Args:
            data: Data to serialize.
            **kwargs: Additional arguments for the serializer.

        Returns:
            Serialized data
        """

    @abstractmethod
    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Unserialize given serialized data.

        Args:
            data: Serialized data to unserialize.
            **kwargs: Additional arguments for the serializer.

        Returns:
            Original data.
        """


class CompressorInterface(ABC):
    """Compressor interface.

    Implement your own compressor inheriting from this class.
    """

    @abstractmethod
    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data.

        Args:
            data: Data to compress.
            level: Desired compression level.

        Returns:
            Raw compressed data.
        """

    @abstractmethod
    def decompress(self, data: bytes) -> bytes:
        """Decompress given compressed data.

        Args:
            data: Compressed data to decompress.

        Returns:
            Original data.
        """


class EncoderInterface(ABC):
    """Encoder interface.

    Implement your own encoder inheriting from this class.

    Note:
        Verify that the encoder alphabet is ASCII (a check is enforced nevertheless).
    """

    @property
    @abstractmethod
    def alphabet(self) -> bytes:
        """Return the encoder alphabet characters.

        This is used to validate that separator characters and flags don't belong
        to this alphabet to prevent malfunctions.
        """

    @abstractmethod
    def encode(self, data: bytes) -> bytes:
        """Encode given data.

        Args:
            data: Data to encode.

        Returns:
            Encoded data.
        """

    @abstractmethod
    def decode(self, data: bytes) -> bytes:
        """Decode given encoded data.

        Args:
            data: Encoded data to decode.

        Returns:
            Original data.
        """
