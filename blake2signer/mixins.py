"""Mixins: abstract classes that provide certain restricted functionality.

They work as a building block for other classes.
"""

import typing
from abc import ABC

from .compressors import ZlibCompressor
from .encoders import B64URLEncoder
from .errors import CompressionError
from .errors import ConversionError
from .errors import DecodeError
from .errors import DecompressionError
from .errors import EncodeError
from .errors import InvalidOptionError
from .errors import SerializationError
from .errors import UnserializationError
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
            raise ConversionError('value can not be converted to bytes') from exc


class SerializerMixin(Mixin, ABC):
    """Serializer mixin.

    Adds serializing capabilities to a subclass.
    """

    # ToDo: D417 is a false positive, see https://github.com/PyCQA/pydocstyle/issues/514
    def __init__(
        self,
        *args: typing.Any,
        serializer: typing.Type[SerializerInterface] = JSONSerializer,
        **kwargs: typing.Any,
    ) -> None:  # noqa: D417
        """Add serializing capabilities.

        Args:
            *args: Additional positional arguments.

        Keyword Args:
            serializer (optional): Serializer class to use (defaults to a JSON
                serializer).
            **kwargs: Additional keyword only arguments.
        """
        self._serializer = serializer()

        personalisation = self._force_bytes(kwargs.get('personalisation', b''))
        personalisation += self._serializer.__class__.__name__.encode()
        kwargs['personalisation'] = personalisation

        super().__init__(*args, **kwargs)

    def _serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Serialize given data.  Additional kwargs are passed to the serializer.

        Args:
            data: data to serialize.

        Keyword Args:
          **kwargs: Additional keyword only arguments for the serializer.

        Returns:
            Serialized data.

        Raises:
            SerializationError: Data can't be serialized.
        """
        try:
            return self._serializer.serialize(data, **kwargs)
        except Exception as exc:
            raise SerializationError('data can not be serialized') from exc

    def _unserialize(self, data: bytes) -> typing.Any:
        """Unserialize given data.

        Args:
            data: serialized data to unserialize.

        Returns:
            Original data.

        Raises:
            UnserializationError: Data can't be unserialized.
        """
        try:
            return self._serializer.unserialize(data)
        except Exception as exc:
            raise UnserializationError('data can not be unserialized') from exc


class CompressorMixin(Mixin, ABC):
    """Compressor mixin.

    Adds compressing capabilities to a subclass.
    """

    # ToDo: D417 is a false positive, see https://github.com/PyCQA/pydocstyle/issues/514
    def __init__(
        self,
        *args: typing.Any,
        compressor: typing.Type[CompressorInterface] = ZlibCompressor,
        compression_flag: typing.Union[str, bytes] = b'.',
        compression_ratio: typing.Union[int, float] = 5.0,
        **kwargs: typing.Any,
    ) -> None:  # noqa: D417
        """Add compressing capabilities.

        Args:
            *args: Additional positional arguments.

        Keyword Args:
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
        """
        self._compressor = compressor()

        personalisation = self._force_bytes(kwargs.get('personalisation', b''))
        personalisation += self._compressor.__class__.__name__.encode()
        kwargs['personalisation'] = personalisation

        self._compression_flag: bytes = self._validate_comp_flag(compression_flag)
        self._compression_ratio: float = self._validate_comp_ratio(compression_ratio)

        super().__init__(*args, **kwargs)

    def _validate_comp_flag(self, flag: typing.Union[str, bytes]) -> bytes:
        """Validate the compression flag value and return it clean.

        Args:
            flag: compression flag to validate.

        Returns:
            Validated compression flag as bytes.

        Raises:
            InvalidOptionError: the compression flag is not valid.
        """
        if not flag:
            raise InvalidOptionError('the compression flag character must have a value')

        if not flag.isascii():
            raise InvalidOptionError('the compression flag character must be ASCII')

        return self._force_bytes(flag)

    @staticmethod
    def _validate_comp_ratio(ratio: float) -> float:
        """Validate the compression ratio value and return it clean.

        Args:
            ratio: compression ratio to validate.

        Returns:
            Validated compression ratio as float.

        Raises:
            InvalidOptionError: the compression ratio is out of bounds.
        """
        if 0.0 <= ratio < 100.0:
            return float(ratio)

        raise InvalidOptionError('the compression ratio must be between 0 and less than 100')

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

        Keyword Args:
            level (optional): Compression level wanted from 1 (least compressed)
                to 9 (most compressed) or None for the default.
            force (optional): Force compression without checking if convenient.

        Returns:
            A tuple containing data, and a flag indicating if data is compressed
            (True) or not.

        Raises:
            CompressionError: Data can't be compressed.
        """
        compression_level = self._compressor.get_compression_level(level)

        try:
            compressed = self._compressor.compress(data, level=compression_level)
        except Exception as exc:
            raise CompressionError('data can not be compressed') from exc

        if force or self._is_significantly_compressed(len(data), len(compressed)):
            return compressed, True

        # Compression isn't reducing size so do nothing.
        return data, False

    def _decompress(self, data: bytes) -> bytes:
        """Decompress given data.

        Args:
            data: compressed data to decompress.

        Returns:
             Original data.

        Raises:
            DecompressionError: Data can't be decompressed.
        """
        try:
            return self._compressor.decompress(data)
        except Exception as exc:
            raise DecompressionError('data can not be decompressed') from exc


class EncoderMixin(Mixin, ABC):
    """Encoder mixin.

    Adds encoding capabilities to a subclass.
    """

    # ToDo: D417 is a false positive, see https://github.com/PyCQA/pydocstyle/issues/514
    def __init__(
        self,
        *args: typing.Any,
        encoder: typing.Type[EncoderInterface] = B64URLEncoder,
        **kwargs: typing.Any,
    ) -> None:  # noqa: D417
        """Add encoding capabilities.

        Args:
            *args: Additional positional arguments.

        Keyword Args:
            encoder (optional): Encoder class to use (defaults to a Base64 URL
                safe encoder).
            **kwargs: Additional keyword only arguments.
        """
        self._encoder = self._validate_encoder(encoder)

        personalisation = self._force_bytes(kwargs.get('personalisation', b''))
        personalisation += self._encoder.__class__.__name__.encode()
        kwargs['personalisation'] = personalisation

        super().__init__(*args, **kwargs)

    @staticmethod
    def _validate_encoder(encoder_class: typing.Type[EncoderInterface]) -> EncoderInterface:
        """Validate the encoder characteristics and return it clean.

        Args:
            encoder_class: encoder class to validate.

        Returns:
            Validated encoder instance.

        Raises:
            InvalidOptionError: the encoder alphabet is empty or is not ASCII.
        """
        encoder = encoder_class()

        if not encoder.alphabet:
            raise InvalidOptionError('the encoder alphabet must have a value')

        if not encoder.alphabet.isascii():
            raise InvalidOptionError('the encoder alphabet must be ASCII')

        return encoder

    def _encode(self, data: bytes) -> bytes:
        """Encode given data.

        Args:
            data: data to encode.

        Returns:
            Encoded data.

        Raises:
            EncodeError: Data can't be encoded.
        """
        try:
            return self._encoder.encode(data)
        except Exception as exc:
            raise EncodeError('data can not be encoded') from exc

    def _decode(self, data: bytes) -> bytes:
        """Decode given encoded data.

        Args:
            data: encoded data to decode.

        Returns:
            Original data.

        Raises:
            DecodeError: Data can't be decoded.
        """
        try:
            return self._encoder.decode(data)
        except Exception as exc:
            raise DecodeError('data can not be decoded') from exc
