"""Serializers: high level classes to serialize and sign data."""

import json
import typing
import zlib
from datetime import timedelta
from hashlib import blake2b
from hashlib import blake2s

from . import errors
from .signers import Blake2Signer
from .signers import Blake2TimestampSigner
from .signers import Hashers_
from .utils import b64decode
from .utils import b64encode


class SignerOptions(typing.TypedDict):
    """Signer options."""

    secret: bytes
    personalisation: bytes
    hasher: Hashers_
    digest_size: int


class Blake2SerializerSigner:
    """Blake2 in keyed hashing mode for signing (optionally timestamped) data.

    It can handle data serialization, compression and encoding.
    """

    Hashers = Hashers_

    DEFAULT_DIGEST_SIZE: int = 16  # 16 bytes is good security/size tradeoff

    COMPRESSION_FLAG: bytes = b'!'  # ascii non-base64 ([a-zA-Z0-9-_=]) symbol!

    __slots__ = (
        '_encoder',
        '_hasher',
        '_max_age',
        '_signer',
    )

    def __init__(
        self,
        secret: bytes,
        *,
        max_age: typing.Union[None, int, float, timedelta] = None,
        personalisation: bytes = b'',
        digest_size: int = DEFAULT_DIGEST_SIZE,
        hasher: Hashers_ = Hashers_.blake2b,
        json_encoder: typing.Optional[typing.Type[json.JSONEncoder]] = None,
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
        :param json_encoder: [optional] A custom JSON encoder class that extends
                             default encoder functionality.

        :raise ConversionError: A parameter is not bytes and can't be converted
                                to bytes.
        :raise InvalidOptionError: A parameter is out of bounds.
        """
        self._encoder: typing.Optional[typing.Type[json.JSONEncoder]] = json_encoder

        self._hasher: typing.Union[typing.Type[blake2b], typing.Type[blake2s]]
        if hasher is self.Hashers.blake2b:
            self._hasher = blake2b
        else:
            self._hasher = blake2s

        personalisation += self.__class__.__name__.encode()

        signer_options: SignerOptions = SignerOptions(
            secret=secret,
            digest_size=digest_size,
            personalisation=personalisation,
            hasher=hasher,
        )

        self._max_age: typing.Union[int, float, timedelta]
        self._signer: typing.Union[Blake2Signer, Blake2TimestampSigner]
        if max_age is None:
            self._signer = Blake2Signer(**signer_options)
            self._max_age = 0
        else:
            self._signer = Blake2TimestampSigner(**signer_options)
            self._max_age = max_age

    def _serialize(self, data: typing.Any) -> bytes:
        """Serialize given data to JSON.

        :raise SerializationError: Data can't be serialized.
        """
        # Other serializers can be used here such as msgpack: msgpack.packb(data)
        try:
            # Use JSON compact encoding
            return json.dumps(data, separators=(',', ':'), cls=self._encoder).encode()
        except TypeError as exc:
            raise errors.SerializationError(exc) from exc

    @staticmethod
    def _unserialize(data: bytes) -> typing.Any:
        """Unserialize given JSON data.

        :raise UnserializationError: Data can't be unserialized.
        """
        # Other serializers can be used here such as msgpack: msgpack.unpackb(data)
        try:
            return json.loads(data)
        except ValueError:
            raise errors.UnserializationError('data can not be unserialized')

    @staticmethod
    def _compress(data: bytes) -> bytes:
        """Compress given data.

        :raise CompressionError: Data can't be compressed.
        """
        # Default level is 6 currently but 5 usually performs better with
        # little compression tradeoff.
        try:
            return zlib.compress(data, level=5)
        except zlib.error as exc:
            raise errors.CompressionError(exc) from exc

    @staticmethod
    def _decompress(data: bytes) -> bytes:
        """Decompress given compressed data.

        :raise DecompressionError: Data can't be decompressed.
        """
        try:
            return zlib.decompress(data)
        except zlib.error:
            raise errors.DecompressionError('data can not be decompressed')

    @staticmethod
    def _encode(data: bytes) -> bytes:
        """Encode given data to base64 URL safe.

        :raise EncodeError: Data can't be encoded.
        """
        try:
            return b64encode(data)
        except (ValueError, TypeError) as exc:
            raise errors.EncodeError(exc) from exc

    @staticmethod
    def _decode(data: typing.AnyStr) -> bytes:
        """Decode given encoded data from base64 URL safe.

        :raise DecodeError: Data can't be decoded.
        """
        try:
            return b64decode(data)
        except (ValueError, TypeError):
            raise errors.DecodeError('data can not be decoded')

    def _add_compression_flag(self, data: bytes) -> bytes:
        """Add the compression flag to given data."""
        return self.COMPRESSION_FLAG + data  # prevents zip bombs

    def _is_compressed(self, data: bytes) -> bool:
        """Return True if given data is compressed, checking the compression flag."""
        return data.startswith(self.COMPRESSION_FLAG, 0, len(self.COMPRESSION_FLAG))

    def _remove_compression_flag(self, data: bytes) -> bytes:
        """Remove the compression flag from given data."""
        return data[len(self.COMPRESSION_FLAG):]

    def dumps(self, data: typing.Any, *, use_compression: bool = False) -> str:
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
                                if lower than ~100bytes. You should choose to enable
                                it based on your knowledge of the average payload
                                size and type.

        :raise SerializationError: Data can't be serialized.
        :raise CompressionError: Data can't be compressed.
        :raise EncodeError: Data can't be encoded.

        :return: A base64 URL safe encoded, signed and optionally timestamped
                 string of serialized and optionally compressed data. This value
                 is safe for printing or transmitting as it only contains the
                 following characters: a-z, A-Z, -, _ and .
        """
        serialized = self._serialize(data)

        if use_compression:
            compressed = self._add_compression_flag(self._compress(serialized))
        else:
            compressed = serialized

        encoded = self._encode(compressed)

        signed = self._signer.sign(encoded)

        return signed.decode()  # since everything is ascii chars this operation is safe

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
        :raise InvalidSignatureError: Signed data has an invalid signature.
        :raise ExpiredSignatureError: Signed data has expired.
        :raise DecodeError: Signed data can't be decoded.
        :raise DecompressionError: Signed data can't be decompressed.
        :raise UnserializationError: Signed data can't be unserialized.

        :return: Unserialized data.
        """
        if isinstance(self._signer, Blake2Signer):
            unsigned = self._signer.unsign(signed_data)
        else:
            unsigned = self._signer.unsign(signed_data, max_age=self._max_age)

        decoded = self._decode(unsigned)

        if self._is_compressed(decoded):
            decompressed = self._decompress(self._remove_compression_flag(decoded))
        else:
            decompressed = decoded

        unserizalized = self._unserialize(decompressed)

        return unserizalized
