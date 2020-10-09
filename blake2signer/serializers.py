"""Serializers: high level classes to serialize and sign data."""

import json
import typing
import zlib
from abc import ABC
from abc import abstractmethod
from datetime import timedelta

from . import errors
from .signers import Blake2TimestampSignerBase
from .signers import Hashers_
from .utils import b64decode
from .utils import b64encode


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
    """

    @abstractmethod
    def encode(self, data: bytes) -> bytes:
        """Encode given data."""

    @abstractmethod
    def decode(self, data: typing.AnyStr) -> bytes:
        """Decode given encoded data."""


class JSONSerializer(SerializerInterface):
    """JSON serializer."""

    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Serialize given data to JSON."""
        return json.dumps(
            data,
            separators=(',', ':'),  # Use JSON compact encoding
            **kwargs,
        ).encode()

    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Unserialize given JSON data."""
        return json.loads(data, **kwargs)


class ZlibCompressor(CompressorInterface):
    """Compressor."""

    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data."""
        return zlib.compress(data, level=level)

    def decompress(self, data: bytes) -> bytes:
        """Decompress given compressed data."""
        return zlib.decompress(data)


class B64URLEncoder(EncoderInterface):
    """Base64 URL safe encoder."""

    def encode(self, data: bytes) -> bytes:
        """Encode given data to base64 URL safe."""
        return b64encode(data)

    def decode(self, data: typing.AnyStr) -> bytes:
        """Decode given encoded data from base64 URL safe."""
        return b64decode(data)


class Blake2SerializerSignerBase(Blake2TimestampSignerBase, ABC):
    """Base class for a timestamp signer that implements `dumps` and `loads`."""

    DEFAULT_DIGEST_SIZE: int = 16  # 16 bytes is good security/size tradeoff

    def __init__(
        self,
        secret: bytes,
        *,
        max_age: typing.Union[None, int, float, timedelta] = None,
        personalisation: bytes = b'',
        digest_size: typing.Optional[int] = None,
        hasher: Hashers_ = Hashers_.blake2b,
    ) -> None:
        """Serialize, sign and verify serialized signed data using Blake2.

        It uses Blake2 in keyed hashing mode.

        Setting `max_age` will produce a timestamped signed stream.

        :param secret: Secret value which will be derived using blake2 to
                       produce the signing key. The minimum secret size is
                       enforced to 16 bytes and there is no maximum since the key
                       will be derived to the maximum supported size.
        :param max_age: [optional] Use a timestamp signer instead of a regular
                        one to ensure that the signature is not older than this
                        time in seconds.
        :param personalisation: [optional] Personalisation string to force the
                                hash function to produce different digests for
                                the same input. It is derived using blake2 to ensure
                                it fits the hasher limits, so it has no practical
                                size limit. It defaults to the class name.
        :param digest_size: [optional] Size of output signature (digest) in bytes
                            (defaults to the minimum size of 16 bytes).
        :param hasher: [optional] Hash function to use: blake2b (default) or blake2s.

        :raise ConversionError: A parameter is not bytes and can't be converted
                                to bytes.
        :raise InvalidOptionError: A parameter is out of bounds.
        """
        if max_age is not None:
            personalisation = self._force_bytes(personalisation) + b'Timestamp'

        self._max_age: typing.Union[None, int, float, timedelta] = max_age

        super().__init__(
            secret,
            personalisation=personalisation,
            digest_size=digest_size or self.DEFAULT_DIGEST_SIZE,
            hasher=hasher,
        )

    def _loads(self, signed_data: bytes) -> bytes:
        """Unsign signed data and get it ready for processing."""
        if self._max_age is None:
            return self._unsign(signed_data)

        return self._unsign_with_timestamp(signed_data, max_age=self._max_age)

    def _dumps(self, data: bytes) -> bytes:
        """Sign given data with a signer or a timestamp signer properly."""
        if self._max_age is None:
            return self._sign(data)

        return self._sign_with_timestamp(data)


class Mixin(Blake2SerializerSignerBase, ABC):
    """Base class for a Blake2DumperSigner mixin."""

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        """Connect mixins with parent."""
        super().__init__(*args, **kwargs)


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
        personalisation += serializer.__name__.encode()
        kwargs['personalisation'] = personalisation

        super().__init__(*args, **kwargs)

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
        personalisation += compressor.__name__.encode()
        kwargs['personalisation'] = personalisation

        super().__init__(*args, **kwargs)

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

        A check is done to verify is compressed data is significantly smaller than
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
        personalisation += encoder.__name__.encode()
        kwargs['personalisation'] = personalisation

        super().__init__(*args, **kwargs)

    def _encode(self, data: bytes) -> bytes:
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


class Blake2SerializerSigner(
        SerializerMixin,
        CompressorMixin,
        EncoderMixin,
):
    """Blake2 for signing and optionally timestamping serialized data.

    It uses Blake2 in keyed hashing mode and it can handle data serialization,
    compression and encoding.
    """

    def __init__(
        self,
        secret: bytes,
        *,
        max_age: typing.Union[None, int, float, timedelta] = None,
        personalisation: bytes = b'',
        digest_size: typing.Optional[int] = None,
        hasher: Hashers_ = Hashers_.blake2b,
        serializer: typing.Type[SerializerInterface] = JSONSerializer,
        compressor: typing.Type[CompressorInterface] = ZlibCompressor,
        encoder: typing.Type[EncoderInterface] = B64URLEncoder,
    ) -> None:
        """Serialize, sign and verify serialized signed data using Blake2.

        It uses Blake2 in keyed hashing mode.

        Setting `max_age` will produce a timestamped signed stream.

        :param secret: Secret value which will be derived using blake2 to
                       produce the signing key. The minimum secret size is
                       enforced to 16 bytes and there is no maximum since the key
                       will be derived to the maximum supported size.
        :param max_age: [optional] Use a timestamp signer instead of a regular
                        one to ensure that the signature is not older than this
                        time in seconds.
        :param personalisation: [optional] Personalisation string to force the
                                hash function to produce different digests for
                                the same input. It is derived using blake2 to ensure
                                it fits the hasher limits, so it has no practical
                                size limit. It defaults to the class name.
        :param digest_size: [optional] Size of output signature (digest) in bytes
                            (defaults to the minimum size of 16 bytes).
        :param hasher: [optional] Hash function to use: blake2b (default) or blake2s.
        :param serializer: [optional] Serializer class to use (defaults to a
                           JSON serializer).
        :param compressor: [optional] Compressor class to use (defaults to a
                           Zlib compressor).
        :param encoder: [optional] Encoder class to use (defaults to a Base64
                        URL safe encoder).

        :raise ConversionError: A parameter is not bytes and can't be converted
                                to bytes.
        :raise InvalidOptionError: A parameter is out of bounds.
        """
        super().__init__(
            secret,
            max_age=max_age,
            personalisation=personalisation,
            digest_size=digest_size,
            hasher=hasher,
            serializer=serializer,
            compressor=compressor,
            encoder=encoder,
        )

    def dumps(
        self,
        data: typing.Any,
        *,
        use_compression: bool = True,
        compression_level: int = 6,
    ) -> str:
        """Serialize and sign data, optionally compressing and/or timestamping it.

        Note that given data is _not_ encrypted, only signed. To recover data from
        the produced string, while validating the signature (and timestamp if any),
        use :meth:`loads`.

        Data will be serialized to JSON and optionally compressed and base64 URL
        safe encoded before being signed. This means that data must be of any
        JSON serializable type: str, int, float, list, tuple, bool, None or dict,
        or a composition of those (tuples are unserialized as lists).

        If `max_age` was specified then the stream will be timestamped.

        A cryptographically secure pseudorandom salt is generated and applied to
        this signature.

        The full flow is as follows, where optional actions are marked between brackets:
        data -> serialize -> [compress] -> [timestamp] -> sign -> encode

        :param data: Any JSON encodable object.
        :param use_compression: [optional] Compress data after serializing it and
                                decompress it before unserializing. For low entropy
                                payloads such as human readable text, it's beneficial
                                from around ~30bytes, and detrimental if smaller.
                                For high entropy payloads like pseudorandom text,
                                it's beneficial from around ~300bytes and detrimental
                                if lower than ~100bytes. You can safely enable it
                                since a size check is done so if compression turns
                                detrimental then it won't be used. If you know
                                from beforehand that data can't be compressed and
                                don't want to waste resources trying, set it to False.
        :param compression_level: [optional] Set the desired compression level
                                  when using compression, where 1 is the fastest
                                  and least compressed and 9 the slowest and most
                                  compressed (defaults to 6).
                                  Note that the performance impact is for both
                                  compression and decompression.

        :raise SerializationError: Data can't be serialized.
        :raise CompressionError: Data can't be compressed or compression level is
                                 invalid.
        :raise EncodeError: Data can't be encoded.

        :return: A base64 URL safe encoded, signed and optionally timestamped
                 string of serialized and optionally compressed data. This value
                 is safe for printing or transmitting as it only contains the
                 following characters: a-z, A-Z, -, _ and .
        """
        serialized = self._serialize(data)

        if use_compression:
            compressed, _ = self._compress(serialized, level=compression_level)
        else:
            compressed = serialized

        encoded = self._encode(compressed)

        return self._dumps(encoded).decode()  # since everything is ascii this is safe

    def loads(self, signed_data: typing.AnyStr) -> typing.Any:
        """Recover original data from a signed serialized string from :meth:`dumps`.

        If `max_age` was specified then it will be ensured that the signature is
        not older than this time in seconds.

        If the data was compressed it will be decompressed before unserializing it.

        Important note: if signed data was timestamped but `max_age` was not
        specified or vice versa then the signature validation will fail.

        The full flow is as follows, where optional actions are marked between brackets:
        data -> check sig -> [check timestamp] -> decode -> [decompress] -> unserialize

        :param signed_data: Signed data to unsign.

        :raise ConversionError: Signed data can't be converted to bytes.
        :raise SignatureError: Signed data structure is not valid.
        :raise InvalidSignatureError: Signed data signature is invalid.
        :raise ExpiredSignatureError: Signed data signature has expired.
        :raise DecodeError: Signed data can't be decoded.
        :raise DecompressionError: Signed data can't be decompressed.
        :raise UnserializationError: Signed data can't be unserialized.

        :return: Unserialized data.
        """
        unsigned = self._loads(self._force_bytes(signed_data))

        decoded = self._decode(unsigned)

        decompressed = self._decompress(decoded)

        unserizalized = self._unserialize(decompressed)

        return unserizalized
