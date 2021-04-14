"""Mixins: abstract classes that provide certain restricted functionality.

They work as a building block for other classes.
"""

import typing
from abc import ABC

from . import errors
from .compressors import ZlibCompressor
from .encoders import B64URLEncoder
from .interfaces import CompressorInterface
from .interfaces import EncoderInterface
from .interfaces import SerializerInterface
from .serializers import JSONSerializer
from .utils import force_bytes


class Mixin(ABC):
    """Base class for a Blake2Signer mixin."""

    @staticmethod
    def _force_bytes(value: typing.AnyStr) -> bytes:
        """Force given value into bytes.

        :raise ConversionError: Can't force value into bytes.
        """
        try:
            return force_bytes(value)
        except Exception:
            raise errors.ConversionError('value can not be converted to bytes')


class SerializerMixin(Mixin, ABC):
    """Serializer mixin.

    Adds serializing capabilities to a subclass.
    """

    def __init__(
        self,
        *args: typing.Any,
        serializer: typing.Type[SerializerInterface] = JSONSerializer,
        **kwargs: typing.Any,
    ) -> None:
        """Add serializing capabilities."""
        self._serializer = serializer()

        personalisation = self._force_bytes(kwargs.get('personalisation', b''))
        personalisation += self._serializer.__class__.__name__.encode()
        kwargs['personalisation'] = personalisation

        super().__init__(*args, **kwargs)  # type: ignore

    def _serialize(self, data: typing.Any) -> bytes:
        """Serialize given data.

        :raise SerializationError: Data can't be serialized.
        """
        try:
            return self._serializer.serialize(data)
        except Exception as exc:
            raise errors.SerializationError(exc) from exc

    def _unserialize(self, data: bytes) -> typing.Any:
        """Unserialize given data.

        :raise UnserializationError: Data can't be unserialized.
        """
        try:
            return self._serializer.unserialize(data)
        except Exception:
            raise errors.UnserializationError('data can not be unserialized')


class CompressorMixin(Mixin, ABC):
    """Compressor mixin.

    Adds compressing capabilities to a subclass.
    """

    COMPRESSION_FLAG: bytes = b'.'  # ascii non-base64 ([a-zA-Z0-9-_=]) symbol!
    COMPRESSION_RATIO: int = 5  # desired minimal compression ratio between 0 and 99

    def __init__(
        self,
        *args: typing.Any,
        compressor: typing.Type[CompressorInterface] = ZlibCompressor,
        **kwargs: typing.Any,
    ) -> None:
        """Add compressing capabilities."""
        self._compressor = compressor()

        personalisation = self._force_bytes(kwargs.get('personalisation', b''))
        personalisation += self._compressor.__class__.__name__.encode()
        kwargs['personalisation'] = personalisation

        super().__init__(*args, **kwargs)  # type: ignore

    def _add_compression_flag(self, data: bytes) -> bytes:
        """Add the compression flag to given data."""
        return self.COMPRESSION_FLAG + data  # prevents zip bombs

    def _is_compressed(self, data: bytes) -> bool:
        """Return True if given data is compressed, checking the compression flag."""
        return data.startswith(self.COMPRESSION_FLAG, 0, len(self.COMPRESSION_FLAG))

    def _remove_compression_flag(self, data: bytes) -> bytes:
        """Remove the compression flag from given data."""
        return data[len(self.COMPRESSION_FLAG):]

    def _is_significantly_compressed(
        self,
        data_size: int,
        compressed_size: int,
    ) -> bool:
        """Return True if the compressed size is significantly lower than data size."""
        return compressed_size < (data_size * (1 - (self.COMPRESSION_RATIO / 100)))

    def _compress(
        self,
        data: bytes,
        *,
        level: int,
        force: bool = False,
    ) -> typing.Tuple[bytes, bool]:
        """Compress given data if convenient or forced, otherwise do nothing.

        A check is done to verify if compressed data is significantly smaller than
        given data and if not then it returns given data as-is, unless compression
        is forced.

        :param data: Data to compress.
        :param level: Compression level wanted.
        :param force: Force compression without checking if convenient.

        :return: A tuple containing data and a flag indicating if data is
                 compressed (True) or not.

        :raise CompressionError: Data can't be compressed.
        """
        try:
            compressed = self._compressor.compress(data, level=level)
        except Exception as exc:
            raise errors.CompressionError(exc) from exc

        if force or self._is_significantly_compressed(len(data), len(compressed)):
            return self._add_compression_flag(compressed), True

        # Compression isn't reducing size so do nothing.
        return data, False

    def _decompress(self, data: bytes) -> bytes:
        """Decompress given data if it is compressed, otherwise do nothing.

        :raise DecompressionError: Data can't be decompressed.
        """
        if not self._is_compressed(data):
            return data

        data = self._remove_compression_flag(data)
        try:
            return self._compressor.decompress(data)
        except Exception:
            raise errors.DecompressionError('data can not be decompressed')


class EncoderMixin(Mixin, ABC):
    """Encoder mixin.

    Adds encoding capabilities to a subclass.
    """

    def __init__(
        self,
        *args: typing.Any,
        encoder: typing.Type[EncoderInterface] = B64URLEncoder,
        **kwargs: typing.Any,
    ) -> None:
        """Add encoding capabilities."""
        self._encoder = encoder()

        personalisation = self._force_bytes(kwargs.get('personalisation', b''))
        personalisation += self._encoder.__class__.__name__.encode()
        kwargs['personalisation'] = personalisation

        super().__init__(*args, **kwargs)  # type: ignore

    def _encode(self, data: typing.AnyStr) -> bytes:
        """Encode given data.

        :raise EncodeError: Data can't be encoded.
        """
        try:
            return self._encoder.encode(data)
        except Exception as exc:
            raise errors.EncodeError(exc) from exc

    def _decode(self, data: typing.AnyStr) -> bytes:
        """Decode given encoded data.

        :raise DecodeError: Data can't be decoded.
        """
        try:
            return self._encoder.decode(data)
        except Exception:
            raise errors.DecodeError('data can not be decoded')
