"""Interfaces: abstract classes to define serializers, encoders and compressors."""

import typing
from abc import ABC
from abc import abstractmethod

from .errors import CompressionError


class SerializerInterface(ABC):
    """Serializer interface.

    Implement any serializer inheriting from this class.
    """

    @abstractmethod
    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Serialize given data.

        Args:
            data: Data to serialize.

        Keyword Args:
            **kwargs: Additional arguments for the serializer.

        Returns:
            Serialized data
        """

    @abstractmethod
    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Unserialize given serialized data.

        Args:
            data: Serialized data to unserialize.

        Keyword Args:
            **kwargs: Additional arguments for the serializer.

        Returns:
            Original data.
        """


class CompressorInterface(ABC):
    """Compressor interface.

    Implement any compressor inheriting from this class.
    """

    @property
    @abstractmethod
    def default_compression_level(self) -> int:
        """Get the default compression level.

        This value is not scaled, it should be the actual default compression level
        for the compressor.
        """

    # noinspection PyMethodMayBeStatic
    def scale_compression_level(self, level: int) -> int:
        """Scale the compression level from 1 to 9 to a valid value for the compressor.

        Override this method if the compressor requires scaling the level.

        Args:
            level: Desired compression level from 1 to 9.

        Returns:
            Scaled compression level for the compressor.
        """
        return level

    def get_compression_level(self, level: typing.Optional[int]) -> int:
        """Return the compression level for the compressor.

        It correctly scales the level if necessary, and returns the corresponding
         default value if no level is indicated.

        Args:
            level: Desired compression level from 1 (least compressed) to 9 (most
                compressed), or None for the default.

        Returns:
            Correct compression level for the compressor.

        Raises:
            CompressionError: The compression level is out of bounds.
        """
        if level is None:
            return self.default_compression_level

        if level < 1 or level > 9:
            raise CompressionError('compression level must be between 1 and 9')

        return self.scale_compression_level(level)

    @abstractmethod
    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data.

        Args:
            data: Data to compress.

        Keyword Args:
            level: Desired compression level adjusted for the compressor.

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

    Implement any encoder inheriting from this class.

    Note:
        Make sure that the encoder alphabet is ASCII (a check is enforced nevertheless).
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
