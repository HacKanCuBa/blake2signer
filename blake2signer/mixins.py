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
    def _force_bytes(value: typing.Any) -> bytes:
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

    def __init__(
        self,
        *args: typing.Any,
        compressor: typing.Type[CompressorInterface] = ZlibCompressor,
        compression_flag: typing.Union[str, bytes] = b'.',
        compression_ratio: typing.Union[int, float] = 5.0,
        **kwargs: typing.Any,
    ) -> None:
        """Add compressing capabilities.

        :param compressor: [optional] Compressor class to use (defaults to a
                           Zlib compressor).
        :param compression_flag: [optional] Character to mark the payload as
                                 compressed. It must be ASCII (defaults to ".").
        :param compression_ratio: [optional] Desired minimal compression ratio,
                                  between 0 and below 100 (defaults to 5).
                                  It is used to calculate when to consider a payload
                                  sufficiently compressed so as to detect detrimental
                                  compression. By default if compression achieves
                                  less than 5% of size reduction, it is considered
                                  detrimental.

        """
        self._compressor = compressor()

        personalisation = self._force_bytes(kwargs.get('personalisation', b''))
        personalisation += self._compressor.__class__.__name__.encode()
        kwargs['personalisation'] = personalisation

        self._compression_flag: bytes = self._validate_comp_flag(compression_flag)
        self._compression_ratio: float = self._validate_comp_ratio(compression_ratio)

        super().__init__(*args, **kwargs)  # type: ignore

    def _validate_comp_flag(self, flag: typing.Union[str, bytes]) -> bytes:
        """Validate the compression flag value and return it clean."""
        if not flag:
            raise errors.InvalidOptionError(
                'the compression flag character must have a value',
            )

        if not flag.isascii():
            raise errors.InvalidOptionError(
                'the compression flag character must be ASCII',
            )

        return self._force_bytes(flag)

    @staticmethod
    def _validate_comp_ratio(ratio_: float) -> float:
        """Validate the compression ratio value and return it clean."""
        ratio = float(ratio_)

        if 0.0 <= ratio < 100.0:
            return ratio

        raise errors.InvalidOptionError(
            'the compression ratio must be between 0 and 99',
        )

    def _add_compression_flag(self, data: bytes) -> bytes:
        """Add the compression flag to given data."""
        return self._compression_flag + data  # prevents zip bombs

    def _is_compressed(self, data: bytes) -> bool:
        """Return True if given data is compressed, checking the compression flag."""
        return data.startswith(self._compression_flag, 0, len(self._compression_flag))

    def _remove_compression_flag(self, data: bytes) -> bytes:
        """Remove the compression flag from given data."""
        return data[len(self._compression_flag):]

    def _is_significantly_compressed(
        self,
        data_size: int,
        compressed_size: int,
    ) -> bool:
        """Return True if the compressed size is significantly lower than data size."""
        return compressed_size < (data_size * (1 - (self._compression_ratio / 100)))

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

    def _encode(self, data: bytes) -> bytes:
        """Encode given data.

        :raise EncodeError: Data can't be encoded.
        """
        try:
            return self._encoder.encode(data)
        except Exception as exc:
            raise errors.EncodeError(exc) from exc

    def _decode(self, data: bytes) -> bytes:
        """Decode given encoded data.

        :raise DecodeError: Data can't be decoded.
        """
        try:
            return self._encoder.decode(data)
        except Exception:
            raise errors.DecodeError('data can not be decoded')
