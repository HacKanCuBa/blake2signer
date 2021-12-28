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

        Args:
            value: Value to convert to bytes.

        Returns:
            Converted value into bytes.

        Raises:
            ConversionError: Can't force value into bytes.
        """
        try:
            return force_bytes(value)
        except Exception as exc:
            raise errors.ConversionError('value can not be converted to bytes') from exc


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
        """Add serializing capabilities.

        Args:
            *args: Additional positional arguments.
            serializer (optional): Serializer class to use (defaults to a JSON
                serializer).
            **kwargs: Additional keyword only arguments.

        Returns:
            None.
        """
        self._serializer = serializer()

        personalisation = self._force_bytes(kwargs.get('personalisation', b''))
        personalisation += self._serializer.__class__.__name__.encode()
        kwargs['personalisation'] = personalisation

        super().__init__(*args, **kwargs)

    def _serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Serialize given data.  Additional kwargs are passed to the serializer.

        Raises:
            SerializationError: Data can't be serialized.
        """
        try:
            return self._serializer.serialize(data, **kwargs)
        except Exception as exc:
            raise errors.SerializationError('data can not be serialized') from exc

    def _unserialize(self, data: bytes) -> typing.Any:
        """Unserialize given data.

        Raises:
            UnserializationError: Data can't be unserialized.
        """
        try:
            return self._serializer.unserialize(data)
        except Exception as exc:
            raise errors.UnserializationError('data can not be unserialized') from exc


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

        Args:
            *args: Additional positional arguments.
            compressor (optional): Compressor class to use (defaults to a Zlib
                compressor).
            compression_flag (optional): Character to mark the payload as compressed.
                It must not belong to the encoder alphabet and be ASCII (defaults
                to ".").
            compression_ratio (optional): Desired minimal compression ratio, between
                0 and below 100 (defaults to 5). It is used to calculate when
                to consider a payload sufficiently compressed to detect detrimental
                compression. By default, if compression achieves less than 5% of
                size reduction, it is considered detrimental.
            **kwargs: Additional keyword only arguments.

        Returns:
            None.
        """
        self._compressor = compressor()

        personalisation = self._force_bytes(kwargs.get('personalisation', b''))
        personalisation += self._compressor.__class__.__name__.encode()
        kwargs['personalisation'] = personalisation

        self._compression_flag: bytes = self._validate_comp_flag(compression_flag)
        self._compression_ratio: float = self._validate_comp_ratio(compression_ratio)

        super().__init__(*args, **kwargs)

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

    def _remove_compression_flag_if_compressed(
        self,
        data: bytes,
    ) -> typing.Tuple[bytes, bool]:
        """Remove the compression flag from given data if it is compressed.

        Args:
            data: Data to process.

        Returns:
              A tuple of given data without the flag, and a boolean indicating
              if it is compressed or not.
        """
        if self._is_compressed(data):
            return self._remove_compression_flag(data), True

        return data, False

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
        level: typing.Optional[int] = None,
        force: bool = False,
    ) -> typing.Tuple[bytes, bool]:
        """Compress given data if convenient or forced, otherwise do nothing.

        A check is done to verify if compressed data is significantly smaller than
        given data and if not then it returns given data as-is, unless compression
        is forced.

        Args:
            data: Data to compress.
            level (optional): Compression level wanted from 1 (least compressed)
                to 9 (most compressed) or None for the default.
            force (optional): Force compression without checking if convenient.

        Returns:
            A tuple containing data, and a flag indicating if data is compressed
            (True) or not.

        Raises
            CompressionError: Data can't be compressed.
        """
        compression_level = self._compressor.get_compression_level(level)

        try:
            compressed = self._compressor.compress(data, level=compression_level)
        except Exception as exc:
            raise errors.CompressionError('data can not be compressed') from exc

        if force or self._is_significantly_compressed(len(data), len(compressed)):
            return compressed, True

        # Compression isn't reducing size so do nothing.
        return data, False

    def _decompress(self, data: bytes) -> bytes:
        """Decompress given data.

        Raises:
            DecompressionError: Data can't be decompressed.
        """
        try:
            return self._compressor.decompress(data)
        except Exception as exc:
            raise errors.DecompressionError('data can not be decompressed') from exc


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
        """Add encoding capabilities.

        Args:
            *args: Additional positional arguments.
            encoder (optional): Encoder class to use (defaults to a Base64 URL
                safe encoder).
            **kwargs: Additional keyword only arguments.

        Returns:
            None.
        """
        self._encoder = self._validate_encoder(encoder)

        personalisation = self._force_bytes(kwargs.get('personalisation', b''))
        personalisation += self._encoder.__class__.__name__.encode()
        kwargs['personalisation'] = personalisation

        super().__init__(*args, **kwargs)

    @staticmethod
    def _validate_encoder(
        encoder_class: typing.Type[EncoderInterface],
    ) -> EncoderInterface:
        """Validate the separator value and return it clean."""
        encoder = encoder_class()

        if not encoder.alphabet:
            raise errors.InvalidOptionError('the encoder alphabet must have a value')

        if not encoder.alphabet.isascii():
            raise errors.InvalidOptionError('the encoder alphabet must be ASCII')

        return encoder

    def _encode(self, data: bytes) -> bytes:
        """Encode given data.

        Raises:
            EncodeError: Data can't be encoded.
        """
        try:
            return self._encoder.encode(data)
        except Exception as exc:
            raise errors.EncodeError('data can not be encoded') from exc

    def _decode(self, data: bytes) -> bytes:
        """Decode given encoded data.

        Raises:
            DecodeError: Data can't be decoded.
        """
        try:
            return self._encoder.decode(data)
        except Exception as exc:
            raise errors.DecodeError('data can not be decoded') from exc
