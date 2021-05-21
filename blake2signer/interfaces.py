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
        """Serialize given data."""

    @abstractmethod
    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Unserialize given serialized data."""


class CompressorInterface(ABC):
    """Compressor interface.

    Implement your own compressor inheriting from this class.
    """

    @abstractmethod
    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data."""

    @abstractmethod
    def decompress(self, data: bytes) -> bytes:
        """Decompress given compressed data."""


class EncoderInterface(ABC):
    """Encoder interface.

    Implement your own encoder inheriting from this class.

    Important note: verify that both the SEPARATOR and the COMPRESSION_FLAG are
    out of the encoder alphabet, otherwise malfunctions will happen!.
    """

    @abstractmethod
    def encode(self, data: bytes) -> bytes:
        """Encode given data."""

    @abstractmethod
    def decode(self, data: bytes) -> bytes:
        """Decode given encoded data."""
