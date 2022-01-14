"""Signers: different classes to sign data."""

import typing
from datetime import timedelta

from . import errors
from .bases import Blake2SerializerSignerBase
from .bases import Blake2Signature
from .bases import Blake2SignatureDump
from .bases import Blake2SignerBase
from .bases import Blake2TimestampSignerBase
from .bases import HasherChoice
from .bases import Secret
from .compressors import ZlibCompressor
from .encoders import B64URLEncoder
from .interfaces import CompressorInterface
from .interfaces import EncoderInterface
from .interfaces import SerializerInterface
from .mixins import CompressorMixin
from .mixins import SerializerMixin
from .serializers import JSONSerializer


class Blake2Signer(Blake2SignerBase):
    """BLAKE in keyed hashing mode for signing data.

    Example:
        >>> data = b'facundo castro presente'
        >>> secret_key = b'a very secret string'
        >>> signer = Blake2Signer(
        >>>     secret_key,
        >>>     personalisation=b'the-data-signer',  # Make it unique per instance
        >>> )
        >>> # Sign, and i.e. store the data in a cookie
        >>> signed: bytes = signer.sign(data)
        >>> cookie = {'data': signed}
        >>> # To verify and recover data simply use unsign: you will either get the
        >>> # data, or a `SignerError` subclass exception (it is recommended to use
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
        it, while validating the signature, use `unsign`.

        The signature and salt are encoded using the chosen encoder.
        Data is left as-is.

        For deterministic signatures, no salt is used. For non-deterministic ones,
        the salt is a cryptographically secure pseudorandom string generated for
        this signature only (meaning that the signature always changes even when
        the payload stays the same).

        If given data is not bytes, a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        bytes to this function.

        Args:
            data: Data to sign.

        Returns:
            A signed stream composed of salt, signature and data.

        Raises:
            ConversionError: Data can't be converted to bytes.
        """
        data_b = self._force_bytes(data)

        return self._compose(data_b, signature=self._sign(data_b))

    def sign_parts(self, data: typing.AnyStr) -> Blake2Signature:
        """Sign given data and produce a container with it and salted signature.

        This method is identical to `sign`, but it produces a container instead
        of a stream, in case of needing to handle data and signature separately.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature, use `unsign_parts`.

        The signature and salt are encoded using the chosen encoder.
        Data is left as-is.

        For deterministic signatures, no salt is used. For non-deterministic ones,
        the salt is a cryptographically secure pseudorandom string generated for
        this signature only (meaning that the signature always changes even when
        the payload stays the same).

        If given data is not bytes, a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        bytes to this function.

        Args:
            data: Data to sign.

        Returns:
            A container with data and its salted signature.

        Raises:
            ConversionError: Data can't be converted to bytes.
        """
        data_b = self._force_bytes(data)

        return Blake2Signature(data=data_b, signature=self._sign(data_b))

    def unsign(self, signed_data: typing.AnyStr) -> bytes:
        """Verify a stream signed by `sign` and recover original data.

        If given data is not bytes, a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        bytes to this function.

        Args:
            signed_data: Signed data to unsign.

        Returns:
            Original data.

        Raises:
            ConversionError: Signed data can't be converted to bytes.
            SignatureError: Signed data structure is not valid.
            InvalidSignatureError: Signed data signature is invalid.
        """
        return self._unsign(self._decompose(self._force_bytes(signed_data)))

    def unsign_parts(
        self,
        signature: typing.Union[Blake2Signature, Blake2SignatureDump],
    ) -> bytes:
        """Verify a container signed by `sign_parts` and recover original data.

        This method is identical to `unsign`, but it reads a container instead of
        a stream.

        If given container is not bytes, a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        a bytes container to this function.

        Args:
            signature: Signed data container to unsign.

        Returns:
            Original data.

        Raises:
            ConversionError: Signed data can't be converted to bytes.
            SignatureError: Signed data structure is not valid.
            InvalidSignatureError: Signed data signature is invalid.
        """
        signature = self._force_bytes_parts(signature)
        # It's easier to just join the parts together and unsign the stream.
        signed_data = self._compose(signature.data, signature=signature.signature)

        return self.unsign(signed_data)


class Blake2TimestampSigner(Blake2TimestampSignerBase):
    """BLAKE in keyed hashing mode for signing data with timestamp.

    Example:
        >>> data = b'facundo castro presente'
        >>> secret_key = b'a very secret string'
        >>> signer = Blake2TimestampSigner(
        >>>     secret_key,
        >>>     personalisation=b'the-data-time-signer',  # Make it unique per instance
        >>> )
        >>> # Sign, and i.e. store the data in a cookie
        >>> signed: bytes = signer.sign(data)
        >>> cookie = {'data': signed}
        >>> # To verify and recover data simply use unsign: you will either get the
        >>> # data, or a `SignerError` subclass exception (it is recommended to use
        >>> # `SignedDataError` given it is more specific and prevents masking other
        >>> # unrelated errors). You need to specify the signature age in seconds
        >>> # (or a timedelta instance). If more than said seconds since the signature
        >>> # was made have passed then an `ExpiredSignatureError` is raised.
        >>> try:
        >>>     unsigned = signer.unsign(cookie.get('data', ''), max_age=10)
        >>> except errors.SignedDataError:
        >>>     # Can't trust given data so set a default, break current process, etc.
        >>>     unsigned = b''

    """

    def sign(self, data: typing.AnyStr) -> bytes:
        """Sign given data and produce a stream of it, timestamp, salt and signature.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature and timestamp, use `unsign`.

        The signature, salt and timestamp are encoded using chosen encoder.
        Data is left as-is.

        For deterministic signatures, no salt is used. For non-deterministic ones,
        the salt is a cryptographically secure pseudorandom string generated for
        this signature only (meaning that the signature always changes even when
        the payload stays the same).

        If given data is not bytes, a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        bytes to this function.

        Args:
            data: Data to sign.

        Returns:
            A signed stream composed of salt, signature, timestamp and data.

        Raises:
            ConversionError: Data can't be converted to bytes.
        """
        data_b = self._force_bytes(data)

        return self._compose(data_b, signature=self._sign_with_timestamp(data_b))

    def sign_parts(self, data: typing.AnyStr) -> Blake2Signature:
        """Sign given data and produce a container of it, timestamp, salt and signature.

        This method is identical to `sign`, but it produces a container instead
        of a stream, in case of needing to handle data and signature separately.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature and timestamp, use `unsign_parts`.

        The signature, salt and timestamp are encoded using chosen encoder.
        Data is left as-is.

        For deterministic signatures, no salt is used. For non-deterministic ones,
        the salt is a cryptographically secure pseudorandom string generated for
        this signature only (meaning that the signature always changes even when
        the payload stays the same).

        If given data is not bytes, a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        bytes to this function.

        Args:
            data: Data to sign.

        Returns:
            A container with data and its timestamped salted signature.

        Raises:
            ConversionError: Data can't be converted to bytes.
        """
        data_b = self._force_bytes(data)

        return Blake2Signature(data=data_b, signature=self._sign_with_timestamp(data_b))

    def unsign(
        self,
        signed_data: typing.AnyStr,
        *,
        max_age: typing.Union[None, int, float, timedelta],
    ) -> bytes:
        """Verify a stream signed and timestamped by `sign` and recover data.

        If given data is not bytes, a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        bytes to this function.

        If `max_age` is not provided, then the timestamp is not checked (the
        signature is always checked).

        Args:
            signed_data: Signed data to unsign.

        Keyword Args:
            max_age (optional): Ensure the signature is not older than this time
                in seconds.

        Returns:
            Original data.

        Raises:
            ConversionError: Signed data can't be converted to bytes.
            SignatureError: Signed data structure is not valid.
            InvalidSignatureError: Signed data signature is invalid.
            ExpiredSignatureError: Signed data signature has expired.
            DecodeError: Timestamp can't be decoded.
        """
        return self._unsign_with_timestamp(
            self._decompose(self._force_bytes(signed_data)),
            max_age=max_age,
        )

    def unsign_parts(
        self,
        signature: typing.Union[Blake2Signature, Blake2SignatureDump],
        *,
        max_age: typing.Union[None, int, float, timedelta],
    ) -> bytes:
        """Verify a container signed by `sign_parts` and recover original data.

        This method is identical to `unsign`, but it reads a container instead of
        a stream.

        If given container is not bytes, a conversion will be applied assuming it's
        UTF-8 encoded. You should prefer to properly encode strings and passing
        a bytes container to this function.

        If `max_age` is not provided, then the timestamp is not checked (the
        signature is always checked).

        Args:
            signature: Signed data container to unsign.

        Keyword Args:
            max_age (optional): Ensure the signature is not older than this time
                in seconds.

        Returns:
            Original data.

        Raises:
            ConversionError: Signed data can't be converted to bytes.
            SignatureError: Signed data structure is not valid.
            InvalidSignatureError: Signed data signature is invalid.
            ExpiredSignatureError: Signed data signature has expired.
            DecodeError: Timestamp can't be decoded.
        """
        sig = self._force_bytes_parts(signature)
        # It's easier to just join the parts together and unsign the stream.
        signed_data = self._compose(sig.data, signature=sig.signature)

        return self.unsign(signed_data, max_age=max_age)


class Blake2SerializerSigner(
        SerializerMixin,
        CompressorMixin,
        Blake2SerializerSignerBase,
):
    """BLAKE for signing and optionally timestamping serialized data.

    It uses BLAKE in keyed hashing mode, and it can handle data serialization,
    compression and encoding.

    Example:
        >>> data = {'message': 'attack at dawn', 'extra': [1, 2, 3, 4]}
        >>> secret_key = b'a very secret string'
        >>> signer = Blake2SerializerSigner(
        >>>     secret_key,
        >>>     max_age=timedelta(days=1),
        >>>     personalisation=b'the-cookie-signer',  # Make it unique per instance
        >>> )
        >>> # Sign, and i.e. store the data in a cookie
        >>> signed: str = signer.dumps(data)  # Compression is enabled by default
        >>> cookie = {'data': signed}
        >>> # To verify and recover data simply use loads: you will either get the
        >>> # data, or a `SignerError` subclass exception (it is recommended to use
        >>> # `SignedDataError` given it is more specific and prevents masking other
        >>> # unrelated errors).
        >>> try:
        >>>     unsigned = signer.loads(cookie.get('data', ''))
        >>> except errors.SignedDataError:
        >>>     # Can't trust given data so set a default, break current process, etc.
        >>>     unsigned = {'message': '', 'extra': []}

    Note:
        If compressing data turns out to be detrimental then data won't be compressed.
        If you know that from beforehand and don't need compression, you can disable it:
        `signed: str = signer.dumps(data, compress=False)`.
        Likewise, you can force compression using:
        `signed: str = signer.dumps(data, force_compression=True)`.

    """

    def __init__(
        self,
        secret: typing.Union[Secret, typing.Sequence[Secret]],
        *,
        max_age: typing.Union[None, int, float, timedelta] = None,
        personalisation: typing.Union[str, bytes] = b'',
        digest_size: typing.Optional[int] = None,
        hasher: typing.Union[HasherChoice, str] = HasherChoice.blake2b,
        deterministic: bool = False,
        separator: typing.Union[str, bytes] = b'.',
        encoder: typing.Type[EncoderInterface] = B64URLEncoder,
        serializer: typing.Type[SerializerInterface] = JSONSerializer,
        compressor: typing.Type[CompressorInterface] = ZlibCompressor,
        compression_flag: typing.Union[str, bytes] = b'.',
        compression_ratio: typing.Union[int, float] = 5.0,
    ) -> None:
        """Serialize, sign and verify serialized signed data using BLAKE.

        It uses BLAKE in keyed hashing mode, and it can handle data serialization,
        compression and encoding.

        Setting `max_age` will produce a timestamped signed stream.

        Args:
            secret: Secret value which will be derived using BLAKE to produce the
                signing key. The minimum secret size is enforced to 16 bytes and there
                is no maximum. You can optionally provide a sequence of secrets, oldest
                to newest, that are used during signature check to allow for secret
                rotation. The last, newest, secret is used for signing.

        Keyword Args:
            max_age (optional): Use a timestamp signer instead of a regular one
                to ensure that the signature is not older than this time in seconds.
            personalisation (optional): Personalisation string to force the hash
                function to produce different digests for the same input. It is
                derived using BLAKE to ensure it fits the hasher limits, so it
                has no practical size limit. It defaults to the class name.
            digest_size (optional): Size of output signature (digest) in bytes
                (defaults to 16 bytes). The minimum size is enforced to 16 bytes.
            hasher (optional): Hash function to use: blake2b (default), blake2s
                or blake3.
            deterministic (optional): Define if signatures are deterministic or
                non-deterministic (default). Non-deterministic sigs are preferred,
                and achieved through the use of a random salt. For deterministic
                sigs, no salt is used: this means that for the same payload, the
                same sig is obtained (the advantage is that the sig is shorter).
                Note that this assumes that the serializer and compressor are
                always deterministic.
            separator (optional): Character to separate the signature and the
                payload. It must not belong to the encoder alphabet and be ASCII
                (defaults to ".").
            encoder (optional): Encoder class to use (defaults to a Base64 URL
                safe encoder).
            serializer (optional): Serializer class to use (defaults to a JSON
                serializer).
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

        Raises:
            ConversionError: A bytes parameter is not bytes and can't be converted
                to bytes.
            InvalidOptionError: A parameter is out of bounds.
        """
        super().__init__(
            secret,
            max_age=max_age,
            personalisation=personalisation,
            digest_size=digest_size,
            hasher=hasher,
            deterministic=deterministic,
            separator=separator,
            serializer=serializer,
            compressor=compressor,
            encoder=encoder,
            compression_flag=compression_flag,
            compression_ratio=compression_ratio,
        )

        if self._compression_flag in self._encoder.alphabet:
            raise errors.InvalidOptionError(
                'the compression flag character must not belong to the encoder alphabet',
            )

    def _dumps(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Dump data serializing it.

        This method serializes data, then compresses it and finally encodes it.

        Args:
            data: Data to serialize.

        Keyword Args:
            compress (bool): Compress data after serializing.
            compression_level (int, optional): Set the desired compression level
                when using compression, where 1 is the fastest and least compressed
                and 9 the slowest and most compressed.
            force_compression (bool): Force compression even if it would be detrimental
                for performance or size. This parameter overrides `compress`.
            serializer_kwargs (dict, optional): Provide keyword arguments for the
                serializer.

        Returns:
            Serialized data.
        """
        compress: bool = kwargs['compress']
        compression_level: typing.Optional[int] = kwargs.get('compression_level')
        force_compression: bool = kwargs['force_compression']
        serializer_kwargs: typing.Dict[str, typing.Any]
        serializer_kwargs = kwargs.get('serializer_kwargs') or {}

        serialized = self._serialize(data, **serializer_kwargs)

        if compress or force_compression:
            compressed, is_compressed = self._compress(
                serialized,
                level=compression_level,
                force=force_compression,
            )
        else:
            compressed, is_compressed = serialized, False

        encoded = self._encode(compressed)
        if is_compressed:
            encoded = self._add_compression_flag(encoded)

        return encoded

    def _loads(self, dumped_data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Load serialized data to recover it.

        This method decodes data, then decompresses it and finally unserializes it.

        Args:
            dumped_data: Data to unserialize.

        Keyword Args:
            **kwargs: Ignored.

        Returns:
            Original data.

        Raises:
            DecodeError: Data can't be decoded.
            DecompressionError: Data can't be decompressed.
            UnserializationError: Data can't be unserialized.
        """
        data, is_compressed = self._remove_compression_flag_if_compressed(dumped_data)

        decoded = self._decode(data)

        decompressed = self._decompress(decoded) if is_compressed else decoded

        unserizalized = self._unserialize(decompressed)

        return unserizalized

    def dumps(
        self,
        data: typing.Any,
        *,
        compress: bool = True,
        compression_level: typing.Optional[int] = None,
        force_compression: bool = False,
        serializer_kwargs: typing.Optional[typing.Dict[str, typing.Any]] = None,
    ) -> str:
        """Serialize and sign data, optionally compressing and/or timestamping it.

        Note that given data is _not_ encrypted, only signed. To recover data from
        the produced string, while validating the signature (and timestamp if any),
        use `loads`.

        Data will be serialized, optionally compressed, and encoded before being
        signed. This means that it must be of any type serializable by the chosen
        serializer, i.e. for a JSON serializer: str, int, float, list, tuple, bool,
        None or dict, or a composition of those (tuples are unserialized as lists).

        If `max_age` was specified then the stream will be timestamped.

        For deterministic signatures, no salt is used. For non-deterministic ones,
        the salt is a cryptographically secure pseudorandom string generated for
        this signature only (meaning that the signature always changes even when
        the payload stays the same).

        The full flow is as follows, where optional actions are marked between brackets:
        data -> serialize -> [compress] -> [timestamp] -> encode -> sign

        Args:
            data: Any serializable object.

        Keyword Args:
            compress (optional): Compress data (default) after serializing it and
                decompress it before unserializing. For low entropy payloads such
                as human-readable text, it's beneficial from around ~30bytes, and
                detrimental if smaller. For high entropy payloads like pseudorandom
                text, it's beneficial from around ~300bytes and detrimental if lower
                than ~100bytes. You can safely enable it since a size check is done
                so if compression turns detrimental then it won't be used. If you
                know from beforehand that data can't be compressed and don't want
                to waste resources trying, set it to False.
            compression_level (optional): Set the desired compression level when
                using compression, where 1 is the fastest and least compressed
                and 9 the slowest and most compressed. The default value depends
                on the compressor being used. Note that the performance impact is
                for both compression and decompression.
            force_compression (optional): Force compression even if it would be
                detrimental for performance or size. This parameter overrides
                `compress`.
            serializer_kwargs (optional): Provide keyword arguments for the serializer.

        Returns:
            An encoded, signed and optionally timestamped string of serialized
            and optionally compressed data. This value is safe for printing or
            transmitting as it only contains the characters supported by the
            encoder and the separator, which are ASCII.

        Raises:
            SerializationError: Data can't be serialized.
            CompressionError: Data can't be compressed or compression level is invalid.
            EncodeError: Data can't be encoded.
        """
        dump = self._dumps(
            data,
            compress=compress,
            compression_level=compression_level,
            force_compression=force_compression,
            serializer_kwargs=serializer_kwargs,
        )

        # since everything is ASCII, decoding is safe
        return self._compose(dump, signature=self._proper_sign(dump)).decode()

    def dumps_parts(
        self,
        data: typing.Any,
        *,
        compress: bool = True,
        compression_level: typing.Optional[int] = None,
        force_compression: bool = False,
        serializer_kwargs: typing.Optional[typing.Dict[str, typing.Any]] = None,
    ) -> Blake2SignatureDump:
        """Serialize and sign data, optionally compressing and/or timestamping it.

        This method is identical to `dumps`, but it dumps into a container instead
        of a stream, in case of needing to handle data and signature separately.

        Note that given data is _not_ encrypted, only signed. To recover data from
        the produced string, while validating the signature (and timestamp if any),
        use `loads_parts`.

        Data will be serialized, optionally compressed, and encoded before being
        signed. This means that it must be of any type serializable by the chosen
        serializer, i.e. for a JSON serializer: str, int, float, list, tuple, bool,
        None or dict, or a composition of those (tuples are unserialized as lists).

        If `max_age` was specified then the stream will be timestamped.

        For deterministic signatures, no salt is used. For non-deterministic ones,
        the salt is a cryptographically secure pseudorandom string generated for
        this signature only (meaning that the signature always changes even when
        the payload stays the same).

        The full flow is as follows, where optional actions are marked between brackets:
        data -> serialize -> [compress] -> [timestamp] -> encode -> sign

        Args:
            data: Any serializable object.

        Keyword Args:
            compress (optional): Compress data (default) after serializing it and
                decompress it before unserializing. For low entropy payloads such
                as human-readable text, it's beneficial from around ~30bytes, and
                detrimental if smaller. For high entropy payloads like pseudorandom
                text, it's beneficial from around ~300bytes and detrimental if lower
                than ~100bytes. You can safely enable it since a size check is done
                so if compression turns detrimental then it won't be used. If you
                know from beforehand that data can't be compressed and don't want
                to waste resources trying, set it to False.
            compression_level (optional): Set the desired compression level when
                using compression, where 1 is the fastest and least compressed
                and 9 the slowest and most compressed. The default value depends
                on the compressor being used. Note that the performance impact is
                for both compression and decompression.
            force_compression (optional): Force compression even if it would be
                detrimental for performance or size. This parameter overrides
                `compress`.
            serializer_kwargs (optional): Provide keyword arguments for the serializer.

        Returns:
            A container with an encoded, signed and optionally timestamped string
            of serialized and optionally compressed data. This value is safe for
            printing or transmitting as it only contains the characters supported
            by the encoder and the separator, which are ASCII.

        Raises:
            SerializationError: Data can't be serialized.
            CompressionError: Data can't be compressed or compression level is invalid.
            EncodeError: Data can't be encoded.
        """
        dump = self._dumps(
            data,
            compress=compress,
            compression_level=compression_level,
            force_compression=force_compression,
            serializer_kwargs=serializer_kwargs,
        )

        # since everything is ASCII, decoding is safe
        return Blake2SignatureDump(
            data=dump.decode(),
            signature=self._proper_sign(dump).decode(),
        )

    def dump(
        self,
        data: typing.Any,
        file: typing.IO,
        *,
        compress: bool = True,
        compression_level: typing.Optional[int] = None,
        force_compression: bool = False,
        serializer_kwargs: typing.Optional[typing.Dict[str, typing.Any]] = None,
    ) -> str:
        """Serialize and sign data to file optionally compressing and/or timestamping it.

        This method is identical to :meth:`dumps`, but it dumps into a file, which
        must be a `.write()`-supporting file-like object, and returns the written
        value for convenience.

        Note that given data is _not_ encrypted, only signed. To recover data from
        the produced string, while validating the signature (and timestamp if any),
        use `loads`.

        Data will be serialized, optionally compressed, and encoded before being
        signed. This means that it must be of any type serializable by the chosen
        serializer, i.e. for a JSON serializer: str, int, float, list, tuple, bool,
        None or dict, or a composition of those (tuples are unserialized as lists).

        If `max_age` was specified then the stream will be timestamped.

        For deterministic signatures, no salt is used. For non-deterministic ones,
        the salt is a cryptographically secure pseudorandom string generated for
        this signature only (meaning that the signature always changes even when
        the payload stays the same).

        The full flow is as follows, where optional actions are marked between brackets:
        data -> serialize -> [compress] -> [timestamp] -> encode -> sign

        Args:
            data: Any serializable object.
            file: A `.write()`-supporting file-like object.

        Keyword Args:
            compress (optional): Compress data (default) after serializing it and
                decompress it before unserializing. For low entropy payloads such
                as human-readable text, it's beneficial from around ~30bytes, and
                detrimental if smaller. For high entropy payloads like pseudorandom
                text, it's beneficial from around ~300bytes and detrimental if lower
                than ~100bytes. You can safely enable it since a size check is done
                so if compression turns detrimental then it won't be used. If you
                know from beforehand that data can't be compressed and don't want
                to waste resources trying, set it to False.
            compression_level (optional): Set the desired compression level when
                using compression, where 1 is the fastest and least compressed
                and 9 the slowest and most compressed. The default value depends
                on the compressor being used. Note that the performance impact is
                for both compression and decompression.
            force_compression (optional): Force compression even if it would be
                detrimental for performance or size. This parameter overrides
                `compress`.
            serializer_kwargs (optional): Provide keyword arguments for the serializer.

        Returns:
            An encoded, signed and optionally timestamped string of serialized
            and optionally compressed data. This value is safe for printing or
            transmitting as it only contains the characters supported by the
            encoder and the separator, which are ASCII.

        Raises:
            SerializationError: Data can't be serialized.
            CompressionError: Data can't be compressed or compression level is invalid.
            EncodeError: Data can't be encoded.
            FileError: File can't be written.
        """
        signed = self.dumps(
            data,
            compress=compress,
            compression_level=compression_level,
            force_compression=force_compression,
            serializer_kwargs=serializer_kwargs,
        )

        # Signed value is ASCII so ConversionError can't happen.
        self._write(file, signed)

        return signed

    def loads(self, signed_data: typing.AnyStr) -> typing.Any:
        """Recover original data from a signed serialized string from `dumps`.

        If `max_age` was specified then it will be ensured that the signature is
        not older than that time in seconds.

        If the data was compressed, it will be decompressed before unserializing it.

        The full flow is as follows, where optional actions are marked between brackets:
        data -> check sig -> [check timestamp] -> decode -> [decompress] -> unserialize

        Args:
            signed_data: Signed data to unsign.

        Returns:
            Original data.

        Raises:
            ConversionError: Signed data can't be converted to bytes.
            SignatureError: Signed data structure is not valid.
            InvalidSignatureError: Signed data signature is invalid.
            ExpiredSignatureError: Signed data signature has expired.
            DecodeError: Signed data can't be decoded.
            DecompressionError: Signed data can't be decompressed.
            UnserializationError: Signed data can't be unserialized.
        """
        parts = self._decompose(self._force_bytes(signed_data))

        return self._loads(self._proper_unsign(parts))

    def loads_parts(
        self,
        signature: typing.Union[Blake2Signature, Blake2SignatureDump],
    ) -> typing.Any:
        """Recover original data from a signed serialized container from `dumps_parts`.

        This method is identical to `loads`, but it reads a container instead of
        a stream.

        If `max_age` was specified then it will be ensured that the signature is
        not older than that time in seconds.

        If the data was compressed, it will be decompressed before unserializing it.

        The full flow is as follows, where optional actions are marked between brackets:
        data -> check sig -> [check timestamp] -> decode -> [decompress] -> unserialize

        Args:
            signature: Signed data container to unsign.

        Returns:
            Original data.

        Raises:
            ConversionError: Signed data can't be converted to bytes.
            SignatureError: Signed data structure is not valid.
            InvalidSignatureError: Signed data signature is invalid.
            ExpiredSignatureError: Signed data signature has expired.
            DecodeError: Signed data can't be decoded.
            DecompressionError: Signed data can't be decompressed.
            UnserializationError: Signed data can't be unserialized.
        """
        sig = self._force_bytes_parts(signature)
        # It's easier to just join the parts together and unsign the stream.
        signed_data = self._compose(sig.data, signature=sig.signature)

        return self.loads(signed_data)

    def load(self, file: typing.IO) -> typing.Any:
        """Recover original data from a signed serialized file from `dump`.

        This method is identical to `loads`, but it reads a file, which
        must be a `.read()`-supporting file-like object.

        If `max_age` was specified then it will be ensured that the signature is
        not older than that time in seconds.

        If the data was compressed, it will be decompressed before unserializing it.

        The full flow is as follows, where optional actions are marked between brackets:
        data -> check sig -> [check timestamp] -> decode -> [decompress] -> unserialize

        Args:
            file: A `.read()`-supporting file-like object containing data to unsign.

        Returns:
            Original data.

        Raises:
            ConversionError: Signed data can't be converted to bytes.
            SignatureError: Signed data structure is not valid.
            InvalidSignatureError: Signed data signature is invalid.
            ExpiredSignatureError: Signed data signature has expired.
            DecodeError: Signed data can't be decoded.
            DecompressionError: Signed data can't be decompressed.
            UnserializationError: Signed data can't be unserialized.
            FileError: File can't be read.
        """
        return self.loads(self._read(file))
