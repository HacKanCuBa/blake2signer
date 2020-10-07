"""Serializers: high level classes to serialize and sign data."""

import json
import typing
import zlib
from datetime import timedelta
from hashlib import blake2b
from hashlib import blake2s

from .errors import DecodeError
from .errors import EncodeError
from .errors import InvalidOptionError
from .signers import Blake2Options
from .signers import Blake2Signer
from .signers import Blake2SignerBase
from .signers import Blake2TimestampSigner
from .signers import Hashers_
from .utils import b64decode
from .utils import b64encode
from .utils import force_bytes


class Blake2SerializerSigner:
    """Blake2 in keyed hashing mode for signing (optionally timestamped) data.

    It can handle data serialization, compression and encoding.
    """

    Hashers = Hashers_

    MIN_SECRET_SIZE: int = Blake2SignerBase.MIN_KEY_SIZE
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
        person: bytes = b'',
        hasher: Hashers_ = Hashers_.blake2b,
        digest_size: int = DEFAULT_DIGEST_SIZE,
        json_encoder: typing.Optional[typing.Type[json.JSONEncoder]] = None,
    ) -> None:
        """Serialize, sign and verify serialized signed data using Blake2.

        It uses Blake2 in keyed hashing mode.

        Setting `max_age` will produce a timestamped signed stream. Using
        compression with `use_compression` may help reducing the size of
        resulting stream.

        Important note: configuration parameters like max_age and use_compression
        are NOT saved in the signed stream so you need to specify them to sign
        and unsign.

        This class is intended to be used to sign and verify cookies or similar.
        It sets sane defaults such as a signature size of 16 bytes, key derivation
        from given secret and the use of a personalisation string.

        It is not supposed to cover all corner cases and be ultimately flexible
        so if you are in need of that please consider using "itsdangerous",
        Django's signer, "pypaseto", "pyjwt" or others like those.

        :param secret: Secret value which will be derived using blake2 to
                       produce the signing key. The minimum secret size is
                       enforced to 16 bytes and there is no maximum since the key
                       will be derived to the maximum supported size.
        :param max_age: [optional] Use a timestamp signer instead of a regular
                        one to ensure that the signature is not older than this
                        time in seconds.
        :param person: [optional] Set the personalisation string to force the hash
                       function to produce different digests for the same input.
                       It is derived using blake2 to ensure it fits the hasher
                       limits, so it has no practical size limit. It defaults
                       to the class name.
        :param hasher: [optional] Hash function to use: blake2b (default) or blake2s.
        :param digest_size: [optional] Size of output signature (digest) in bytes
                            (defaults to 16 bytes).
        :param json_encoder: [optional] A custom JSON encoder class that extends
                             default encoder functionality.

        :raise InvalidOptionError: A parameter is out of bounds.
        """
        self._encoder: typing.Optional[typing.Type[json.JSONEncoder]] = json_encoder

        self._hasher: typing.Union[typing.Type[blake2b], typing.Type[blake2s]]
        if hasher is self.Hashers.blake2b:
            self._hasher = blake2b
        else:
            self._hasher = blake2s

        secret, person = force_bytes(secret), force_bytes(person)

        if len(secret) < self.MIN_SECRET_SIZE:
            raise InvalidOptionError(
                f'secret should be longer than {self.MIN_SECRET_SIZE} bytes',
            )

        # read more about personalisation in the hashlib docs:
        # https://docs.python.org/3/library/hashlib.html#personalisation
        if not person:
            person = self.__class__.__name__.encode()

        person = self.derive_person(person)

        # mypy issue: https://github.com/python/mypy/issues/8890
        signer_options: Blake2Options = Blake2Options(
            key=self.derive_key(secret, person=person),
            digest_size=digest_size,
            person=person,
        )

        self._max_age: typing.Union[int, float, timedelta]
        self._signer: typing.Union[Blake2Signer, Blake2TimestampSigner]
        if max_age is None:
            self._signer = Blake2Signer(hasher=hasher, **signer_options)
            self._max_age = 0
        else:
            self._signer = Blake2TimestampSigner(hasher=hasher, **signer_options)
            self._max_age = max_age

    def derive_person(self, person: bytes) -> bytes:
        """Derive given personalisation value to ensure it fits the hasher correctly."""
        return self._hasher(person, digest_size=self._hasher.PERSON_SIZE).digest()

    def derive_key(self, secret: bytes, *, person: bytes = b'') -> bytes:
        """Derive given secret to ensure it fits correctly as the hasher key."""
        return self._hasher(
            secret,
            person=person,
            digest_size=self._hasher.MAX_KEY_SIZE,
        ).digest()

    def _serialize(self, data: typing.Any) -> bytes:
        """Serialize given data to JSON."""
        # Other serializers can be used here such as msgpack: msgpack.packb(data)
        try:
            # Use JSON compact encoding
            return json.dumps(data, separators=(',', ':'), cls=self._encoder).encode()
        except TypeError as exc:
            raise EncodeError(exc) from exc

    @staticmethod
    def _unserialize(data: bytes) -> typing.Any:
        # Other serializers can be used here such as msgpack: msgpack.unpackb(data)
        try:
            return json.loads(data)
        except ValueError:
            raise DecodeError('data can not be unserialized')

    @staticmethod
    def _compress(data: bytes) -> bytes:
        # Default level is 6 currently but 5 usually performs better with
        # little compression tradeoff.
        try:
            return zlib.compress(data, level=5)
        except zlib.error as exc:
            raise EncodeError(exc) from exc

    @staticmethod
    def _decompress(data: bytes) -> bytes:
        try:
            return zlib.decompress(data)
        except zlib.error:
            raise DecodeError('data can not be decompressed')

    @staticmethod
    def _encode(data: bytes) -> bytes:
        try:
            return b64encode(data)
        except (ValueError, TypeError) as exc:
            raise EncodeError(exc) from exc

    @staticmethod
    def _decode(data: typing.AnyStr) -> bytes:
        try:
            return b64decode(data)
        except (ValueError, TypeError):
            raise DecodeError('invalid base64 data')

    def _add_compression_flag(self, data: bytes) -> bytes:
        """Add the compression flag to given data."""
        return self.COMPRESSION_FLAG + data  # prevents zip bombs

    def _is_compressed(self, data: bytes) -> bool:
        """Return True if given data is compressed, checking the compression flag."""
        return data.startswith(self.COMPRESSION_FLAG, 0, len(self.COMPRESSION_FLAG))

    def _remove_compression_flag(self, data: bytes) -> bytes:
        """Remove the compression flag from given data."""
        return data[len(self.COMPRESSION_FLAG):]

    @staticmethod
    def _signed_data_bytes(signed_data: typing.AnyStr) -> bytes:
        """Force given signed data into bytes.

        :raise DecodeError: Can't convert to bytes.
        """
        try:
            return force_bytes(signed_data)
        except Exception:
            raise DecodeError('signed data can not be encoded to bytes')

    def dumps(self, data: typing.Any, *, use_compression: bool = False) -> str:
        """Serialize and sign data, optionally compressing and/or timestamping it.

        Data will be serialized to JSON and optionally compressed before being
        signed. This means that data must be of any JSON serializable type: str,
        int, list or dict, or a composition of those (tuples are unserialized as
        lists).

        If `max_age` was specified then the stream will be timestamped.
        The stream is also salted by a cryptographically secure pseudorandom
        string generated for this signature only.

        The resulting stream is base64 encoded.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature (and timestamp if any), use :meth:`loads`.

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

        :raise EncodeError: Data could not be encoded.

        :return: A base64 encoded, signed and optionally timestamped stream of data.
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

        If the data was compressed it will be decompressed before unserializing it.

        If `max_age` was specified then it will be ensured that the signature is
        not older than this time in seconds.

        Important note: if signed data was timestamped but `max_age` was not
        specified then an error will occur. The same goes for the other way
        around: if it wasn't timestamped but `max_age` is now set. So you need to
        know these parameters from beforehand: they won't live in the signed stream!

        The full flow is as follows, where optional actions are marked between brackets:
        data -> check sig -> [check timestamp] -> decode -> [decompress] -> unserialize

        :param signed_data: Signed data to unsign.

        :raise DecodeError: Signed data is not valid or it can't be decoded.
        :raise InvalidSignatureError: Signed data has invalid signature.
        :raise ExpiredSignatureError: Signed data has expired.

        :return: Unserialized data.
        """
        # Unfortunately I have to do this operation before checking the signature
        # and there's no other way around it since the hashers only support
        # bytes-like objects. Both itsdangerous and Django do this too.
        signed_data_bytes = self._signed_data_bytes(signed_data)

        if isinstance(self._signer, Blake2Signer):
            unsigned = self._signer.unsign(signed_data_bytes)
        else:
            unsigned = self._signer.unsign(signed_data_bytes, max_age=self._max_age)

        decoded = self._decode(unsigned)

        if self._is_compressed(decoded):
            decompressed = self._decompress(self._remove_compression_flag(decoded))
        else:
            decompressed = decoded

        unserizalized = self._unserialize(decompressed)

        return unserizalized
