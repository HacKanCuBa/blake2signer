"""Signers: different classes to sign data."""

import typing
from datetime import timedelta

from .bases import Blake2SerializerSignerBase
from .bases import Blake2SignerBase
from .bases import Blake2TimestampSignerBase
from .bases import HasherChoice
from .compressors import ZlibCompressor
from .encoders import B64URLEncoder
from .interfaces import CompressorInterface
from .interfaces import EncoderInterface
from .interfaces import SerializerInterface
from .mixins import CompressorMixin
from .mixins import EncoderMixin
from .mixins import SerializerMixin
from .serializers import JSONSerializer


class Blake2Signer(Blake2SignerBase):
    """Blake2 in keyed hashing mode for signing data.

    :Example:

    >>> data = b'facundo castro presente'
    >>> secret_key = b'a very secret string'
    >>> signer = Blake2Signer(
    >>>     secret_key,
    >>>     personalisation=b'the-data-signer',  # Make it unique per instance
    >>> )
    >>> # Sign and i.e. store the data in a cookie
    >>> signed: bytes = signer.sign(data)
    >>> cookie = {'data': signed}
    >>> # To verify and recover data simply use unsign: you will either get the
    >>> # data or a `SignerError` subclass exception (it is recommended to use
    >>> # `SignedDataError` given it is more specific and prevents masking other
    >>> # unrelated errors).
    >>> try:
    >>>     unsigned = signer.unsign(cookie.get('data', ''))
    >>> except errors.SignedDataError:
    >>>     # Can't trust given data so set a default, break current process, etc.
    >>>     unsigned = b''

    """

    def sign(self, data: typing.AnyStr) -> bytes:
        """Sign given data and produce a stream composed of it, salt and signature.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature, use :meth:`unsign`.

        The signature and salt are base64 URL safe encoded without padding.
        Data is left as-is.

        The salt is a cryptographically secure pseudorandom string generated for
        this signature only making it non-deterministic (meaning that the signature
        always changes even when the payload stays the same).

        If given data is not bytes a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        bytes to this function.

        :raise ConversionError: Data can't be converted to bytes.

        :return: A signed stream composed of salt, signature and data.
        """
        return self._sign(self._force_bytes(data))

    def unsign(self, signed_data: typing.AnyStr) -> bytes:
        """Verify a stream signed by :meth:`sign` and recover original data.

        If given data is not bytes a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        bytes to this function.

        :param signed_data: Signed data to unsign.

        :raise ConversionError: Signed data can't be converted to bytes.
        :raise SignatureError: Signed data structure is not valid.
        :raise InvalidSignatureError: Signed data signature is invalid.

        :return: Original data.
        """
        # Unfortunately I have to do this operation before checking the signature
        # and there's no other way around it since the hashers only support
        # bytes-like objects. Both itsdangerous and Django do this too.
        return self._unsign(self._force_bytes(signed_data))


class Blake2TimestampSigner(Blake2TimestampSignerBase):
    """Blake2 in keyed hashing mode for signing data with timestamp.

    :Example:

    >>> data = b'facundo castro presente'
    >>> secret_key = b'a very secret string'
    >>> signer = Blake2TimestampSigner(
    >>>     secret_key,
    >>>     personalisation=b'the-data-time-signer',  # Make it unique per instance
    >>> )
    >>> # Sign and i.e. store the data in a cookie
    >>> signed: bytes = signer.sign(data)
    >>> cookie = {'data': signed}
    >>> # To verify and recover data simply use unsign: you will either get the
    >>> # data or a `SignerError` subclass exception (it is recommended to use
    >>> # `SignedDataError` given it is more specific and prevents masking other
    >>> # unrelated errors). You need to specify the signature age in seconds
    >>> # (or a timedelta instance).
    >>> try:
    >>>     unsigned = signer.unsign(cookie.get('data', ''), max_age=10)
    >>> except errors.SignedDataError:
    >>>     # Can't trust given data so set a default, break current process, etc.
    >>>     unsigned = b''

    """

    def sign(self, data: typing.AnyStr) -> bytes:
        """Sign given data and produce a stream of it, timestamp, salt and signature.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature and timestamp, use :meth:`unsign`.

        The signature, salt and timestamp are base64 URL safe encoded without
        padding. Data is left as-is.

        The salt is a cryptographically secure pseudorandom string generated for
        this signature only making it non-deterministic (meaning that the signature
        always changes even when the payload stays the same).

        If given data is not bytes a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        bytes to this function.

        :raise ConversionError: Data can't be converted to bytes.

        :return: A signed stream composed of salt, signature, timestamp and data.
        """
        return self._sign_with_timestamp(self._force_bytes(data))

    def unsign(
        self,
        signed_data: typing.AnyStr,
        *,
        max_age: typing.Union[int, float, timedelta],
    ) -> bytes:
        """Verify a stream signed and timestamped by :meth:`sign` and recover data.

        If given data is not bytes a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        bytes to this function.

        :param signed_data: Signed data to unsign.
        :param max_age: Ensure the signature is not older than this time in seconds.

        :raise ConversionError: Signed data can't be converted to bytes.
        :raise SignatureError: Signed data structure is not valid.
        :raise InvalidSignatureError: Signed data signature is invalid.
        :raise ExpiredSignatureError: Signed data signature has expired.

        :return: Original data.
        """
        # Unfortunately I have to do this operation before checking the signature
        # and there's no other way around it since the hashers only support
        # bytes-like objects. Both itsdangerous and Django do this too.
        return self._unsign_with_timestamp(
            self._force_bytes(signed_data),
            max_age=max_age,
        )


class Blake2SerializerSigner(
        SerializerMixin,
        CompressorMixin,
        EncoderMixin,
        Blake2SerializerSignerBase,
):
    """Blake2 for signing and optionally timestamping serialized data.

    It uses Blake2 in keyed hashing mode and it can handle data serialization,
    compression and encoding.

    :Example:

    >>> data = {'message': 'attack at dawn', 'extra': [1, 2, 3, 4]}
    >>> secret_key = b'a very secret string'
    >>> signer = Blake2SerializerSigner(
    >>>     secret_key,
    >>>     max_age=timedelta(days=1),
    >>>     personalisation=b'the-cookie-signer',  # Make it unique per instance
    >>> )
    >>> # Sign and i.e. store the data in a cookie
    >>> signed: str = signer.dumps(data)  # Compression is enabled by default
    >>> cookie = {'data': signed}
    >>> # To verify and recover data simply use loads: you will either get the
    >>> # data or a `SignerError` subclass exception (it is recommended to use
    >>> # `SignedDataError` given it is more specific and prevents masking other
    >>> # unrelated errors).
    >>> try:
    >>>     unsigned = signer.loads(cookie.get('data', ''))
    >>> except errors.SignedDataError:
    >>>     # Can't trust given data so set a default, break current process, etc.
    >>>     unsigned = {'message': '', 'extra': []}

    .. note:: If compressing data turns out to be detrimental then data won't be
              compressed. If you know that from beforehand and don't need
              compression, you can disable it:
              `signed: str = signer.dumps(data, use_compression=False)`.
              Likewise, you can force compression using:
              `signed: str = signer.dumps(data, force_compression=True)`.

    """

    def __init__(
        self,
        secret: bytes,
        *,
        max_age: typing.Union[None, int, float, timedelta] = None,
        personalisation: bytes = b'',
        digest_size: typing.Optional[int] = None,
        hasher: typing.Union[HasherChoice, str] = HasherChoice.blake2b,
        deterministic: bool = False,
        serializer: typing.Type[SerializerInterface] = JSONSerializer,
        compressor: typing.Type[CompressorInterface] = ZlibCompressor,
        encoder: typing.Type[EncoderInterface] = B64URLEncoder,
    ) -> None:
        """Serialize, sign and verify serialized signed data using Blake2.

        It uses Blake2 in keyed hashing mode and it can handle data serialization,
        compression and encoding.

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
                            (defaults to the minimum allowed size of 16 bytes).
        :param hasher: [optional] Hash function to use: blake2b (default) or blake2s.
        :param deterministic: [optional] Define if signatures are deterministic
                              or non-deterministic (default). Non-deterministic
                              sigs are preferred, and achieved through the use of a
                              random salt. For deterministic sigs, no salt is used:
                              this means that for the same payload, the same sig is
                              obtained (the advantage is that the sig is shorter).
                              Note that this assumes that the serializer and
                              compressor are always deterministic.
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
            deterministic=deterministic,
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
        force_compression: bool = False,
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
        this signature making it non-deterministic (meaning that the signature
        always changes even when the payload stays the same).

        The full flow is as follows, where optional actions are marked between brackets:
        data -> serialize -> [compress] -> [timestamp] -> encode -> sign

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
        :param force_compression: [optional] Force compression even if it would
                                  be detrimental for performance or size. This
                                  parameter overrides `use_compression`.

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

        if use_compression or force_compression:
            compressed, _ = self._compress(
                serialized,
                level=compression_level,
                force=force_compression,
            )
        else:
            compressed = serialized

        encoded = self._encode(compressed)

        return self._dumps(encoded).decode()  # since everything is ascii this is safe

    def loads(self, signed_data: typing.AnyStr) -> typing.Any:
        """Recover original data from a signed serialized string from :meth:`dumps`.

        If `max_age` was specified then it will be ensured that the signature is
        not older than that time in seconds.

        If the data was compressed it will be decompressed before unserializing it.

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
