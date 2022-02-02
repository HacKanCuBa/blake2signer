"""Bases: base classes for signers."""

import os
import typing
from abc import ABC
from abc import abstractmethod
from datetime import timedelta
from secrets import compare_digest
from time import time

from .encoders import B64URLEncoder
from .errors import ExpiredSignatureError
from .errors import FileError
from .errors import InvalidOptionError
from .errors import InvalidSignatureError
from .errors import SignatureError
from .hashers import BLAKE2Hasher
from .hashers import BLAKE3Hasher
from .hashers import BLAKEHasher
from .hashers import HasherChoice
from .interfaces import EncoderInterface
from .mixins import EncoderMixin
from .mixins import Mixin
from .utils import file_mode_is_text
from .utils import ordinal
from .utils import timestamp_to_aware_datetime


class SignedDataParts(typing.NamedTuple):
    """Parts of a signed data container."""

    data: bytes
    salt: bytes
    signature: bytes


class TimestampedDataParts(typing.NamedTuple):
    """Parts of a timestamped data container."""

    data: bytes
    timestamp: int


class Blake2SignatureDump(typing.NamedTuple):
    """Signature container."""

    signature: str  # Composite signature
    data: str


class Blake2Signature(typing.NamedTuple):
    """Signature container."""

    signature: bytes  # Composite signature
    data: bytes


Secret = typing.Union[str, bytes]


class Base(Mixin, ABC):
    """Base class containing the minimum for a signer."""

    Hashers = HasherChoice  # Sugar to avoid having to import the enum

    MIN_SECRET_SIZE: int = 16
    """Minimum secret size allowed (during instantiation)."""

    MIN_DIGEST_SIZE: int = 16
    """Minimum digest size allowed (during instantiation)."""

    DEFAULT_DIGEST_SIZE: int = 16  # 16 bytes is good security/size tradeoff
    """Default digest size to use when no digest size is indicated."""

    def __init__(
        self,
        secret: typing.Union[Secret, typing.Sequence[Secret]],
        *,
        personalisation: typing.Union[str, bytes] = b'',
        digest_size: typing.Optional[int] = None,
        hasher: typing.Union[HasherChoice, str] = HasherChoice.blake2b,
        deterministic: bool = False,
        separator: typing.Union[str, bytes] = b'.',
    ) -> None:
        """Sign and verify signed data using BLAKE in keyed hashing mode.

        Args:
            secret: Secret value which will be derived using BLAKE to produce the
                signing key. The minimum secret size is enforced to 16 bytes and there
                is no maximum. You can optionally provide a sequence of secrets, oldest
                to newest, that are used during signature check to allow for secret
                rotation. The last, newest, secret is used for signing.

        Keyword Args:
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
            separator (optional): Character to separate the signature and the
                payload. It must not belong to the encoder alphabet and be ASCII
                (defaults to ".").

        Raises:
            ConversionError: A bytes parameter is not bytes and can't be converted
                to bytes.
            InvalidOptionError: A parameter is out of bounds.
        """
        hasher_choice = self._validate_hasher_choice(hasher)
        digest_size = self._validate_digest_size(digest_size)
        separator = self._validate_separator(separator)
        person = self._validate_person(personalisation)
        secrets = self._validate_secret(secret)

        if deterministic:
            person += b'Deterministic'
        person += self.__class__.__name__.encode()

        self._deterministic: bool = deterministic
        self._separator: bytes = separator

        self._hasher = self._get_hasher(
            hasher_choice,
            secrets=secrets,
            digest_size=digest_size,
            person=person,
        )

    def _validate_secret(
        self,
        secret: typing.Union[Secret, typing.Sequence[Secret]],
    ) -> typing.Tuple[bytes, ...]:
        """Validate the secret value and return it clean.

        Args:
            secret: Secret value to validate.

        Returns:
            Cleaned secrets tuple.

        Raises:
            ConversionError: The value is not bytes and can't be converted to bytes.
            InvalidOptionError: The value is out of bounds.
        """

        def coerce(secret_: Secret, position_: int) -> bytes:
            """Coerce a given secret into bytes.

            Args:
                secret_: Secret value to validate.
                position_: Position of the secret in the sequence.

            Returns:
                A secret value as bytes.

            Raises:
                InvalidOptionError: the secret in given position is invalid.
            """
            coerced = self._force_bytes(secret_)
            if len(coerced) < self.MIN_SECRET_SIZE:
                raise InvalidOptionError(
                    f'the {ordinal(position_)} secret should be longer than '
                    + f'{self.MIN_SECRET_SIZE} bytes',
                )

            return coerced

        secrets: typing.Sequence[Secret]
        if isinstance(secret, (str, bytes)):
            secrets = [secret]
        else:
            secrets = secret

        return tuple(coerce(dirty, position) for position, dirty in enumerate(secrets, start=1))

    def _validate_person(self, person: typing.Union[str, bytes]) -> bytes:
        """Validate the personalisation value and return it clean.

        Args:
            person: Personalisation value to validate.

        Returns:
            Cleaned personalisation value.

        Raises:
            ConversionError: The value is not bytes and can't be converted to bytes.
        """
        return self._force_bytes(person)

    def _validate_digest_size(self, digest_size: typing.Optional[int]) -> int:
        """Validate the digest_size value and return it clean.

        Args:
            digest_size: Digest size value to validate.

        Returns:
            Cleaned digest size value.

        Raises:
            InvalidOptionError: The value is out of bounds.
        """
        if digest_size is None:
            digest_size = self.DEFAULT_DIGEST_SIZE

        if digest_size < self.MIN_DIGEST_SIZE:
            raise InvalidOptionError(
                f'digest_size should be bigger than or equal to {self.MIN_DIGEST_SIZE}',
            )

        return digest_size

    @staticmethod
    def _validate_hasher_choice(hasher: typing.Union[HasherChoice, str]) -> HasherChoice:
        """Validate the hasher choice.

        Args:
            hasher: the hasher choice to validate.

        Returns:
            A validated hasher choice as HasherChoice.

        Raises:
            InvalidOptionError: Invalid hasher choice.
        """
        try:
            choice = HasherChoice(hasher)
        except ValueError:
            raise InvalidOptionError(
                f'invalid hasher choice, must be one of: {", ".join(h for h in HasherChoice)}',
            )

        return choice

    def _validate_separator(self, separator: typing.Union[str, bytes]) -> bytes:
        """Validate the separator value and return it clean.

        Args:
            separator: Separator value to validate.

        Returns:
            Cleaned separator value.

        Raises:
            ConversionError: The value is not bytes and can't be converted to bytes.
            InvalidOptionError:  The value is out of bounds.
        """
        if not separator:
            raise InvalidOptionError('the separator character must have a value')

        if not separator.isascii():
            raise InvalidOptionError('the separator character must be ASCII')

        return self._force_bytes(separator)

    @staticmethod
    def _get_hasher(
        hasher: HasherChoice,
        *,
        secrets: typing.Tuple[bytes, ...],
        digest_size: int,
        person: bytes,
    ) -> BLAKEHasher:
        """Get the proper hasher instance regarding the choice."""
        hasher_class: typing.Type[BLAKEHasher]

        if hasher in {HasherChoice.blake2b, HasherChoice.blake2s}:
            hasher_class = BLAKE2Hasher
        else:
            hasher_class = BLAKE3Hasher

        return hasher_class(
            hasher,
            secrets=secrets,
            digest_size=digest_size,
            person=person,
        )


class Blake2SignerBase(EncoderMixin, Base, ABC):
    """Base class for a signer based on BLAKE in keyed hashing mode."""

    def __init__(
        self,
        secret: typing.Union[Secret, typing.Sequence[Secret]],
        *,
        personalisation: typing.Union[str, bytes] = b'',
        digest_size: typing.Optional[int] = None,
        hasher: typing.Union[HasherChoice, str] = HasherChoice.blake2b,
        deterministic: bool = False,
        separator: typing.Union[str, bytes] = b'.',
        encoder: typing.Type[EncoderInterface] = B64URLEncoder,
    ) -> None:
        """Sign and verify signed data using BLAKE in keyed hashing mode.

        Args:
            secret: Secret value which will be derived using BLAKE to produce the
                signing key. The minimum secret size is enforced to 16 bytes and there
                is no maximum. You can optionally provide a sequence of secrets, oldest
                to newest, that are used during signature check to allow for secret
                rotation. The last, newest, secret is used for signing.

        Keyword Args:
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
            separator (optional): Character to separate the signature and the
                payload. It must not belong to the encoder alphabet and be ASCII
                (defaults to ".").
            encoder (optional): Encoder class to use for the signature, nothing
                else is encoded (defaults to a Base64 URL safe encoder).

        Raises:
            ConversionError: A bytes parameter is not bytes and can't be converted
                to bytes.
            InvalidOptionError: A parameter is out of bounds.
        """
        super().__init__(
            secret,
            personalisation=personalisation,
            digest_size=digest_size,
            hasher=hasher,
            separator=separator,
            deterministic=deterministic,
            encoder=encoder,
        )

    def _validate_separator(self, separator: typing.Union[str, bytes]) -> bytes:
        """Validate the separator value and return it clean.

        Args:
            separator: Separator value to validate.

        Returns:
            Cleaned separator value.

        Raises:
            ConversionError: The value is not bytes and can't be converted to bytes.
            InvalidOptionError: The value is out of bounds.
        """
        sep = super()._validate_separator(separator)

        if sep in self._encoder.alphabet:
            raise InvalidOptionError(
                'the separator character must not belong to the encoder alphabet',
            )

        return sep

    def _get_salt(self) -> bytes:
        """Get a salt for the signature considering its type.

        For non-deterministic signatures, a pseudo random salt is generated.

        Returns:
            A pseudorandom salt for the signature if non-deterministic, otherwise an
            empty bytes string.
        """
        if self._deterministic:
            return b''

        salt_size = self._hasher.salt_size
        salt = os.urandom(salt_size)
        # Produce an encoded salt to use it as is, so we don't have to deal with
        # decoding it when unsigning. The only downside is that we loose a few
        # bits, but it's tolerable since we are using the maximum allowed size.
        return self._encode(salt)[:salt_size]

    def _force_bytes_parts(
        self,
        signature: typing.Union[Blake2Signature, Blake2SignatureDump],
    ) -> Blake2Signature:
        """Force given value into bytes, meaning a Blake2Signature container."""
        return Blake2Signature(
            data=self._force_bytes(signature.data),
            signature=self._force_bytes(signature.signature),
        )

    def _compose(self, data: bytes, *, signature: bytes) -> bytes:
        """Compose data and signature into a single stream."""
        return signature + self._separator + data

    def _decompose(self, signed_data: bytes) -> SignedDataParts:
        """Decompose a signed data stream into its parts.

        Args:
            signed_data: the signed data stream to decompose.

        Returns:
            The decomposed signed data in a container.

        Raises:
            SignatureError: Invalid signed data.
        """
        if self._separator not in signed_data:
            raise SignatureError('separator not found in signed data')

        composite_signature, data = signed_data.split(self._separator, 1)

        if not composite_signature:
            raise SignatureError('signature information is missing')

        if self._deterministic:
            salt = b''
            signature = composite_signature
        else:
            salt_size = self._hasher.salt_size
            salt = composite_signature[:salt_size]
            signature = composite_signature[salt_size:]

        return SignedDataParts(data=data, salt=salt, signature=signature)

    def _signify(self, *, data: bytes, salt: bytes, key: bytes) -> bytes:
        """Return signature for given data using salt and all the hasher options.

        The signature is encoded using the chosen encoder.

        Keyword Args:
            data: data to sign.
            salt: salt to use in the signature.
            key: the signing key.

        Returns:
            An encoded signature.
        """
        signature = self._hasher.digest(data, key=key, salt=salt)

        return self._encode(signature)

    def _sign(self, data: bytes) -> bytes:
        """Sign given data and produce a signature stream composed of salt and signature.

        The signature stream (salt and signature) is encoded using the chosen encoder.

        Args:
            data: data to sign.

        Returns:
            A signature stream containing salt and signature.
        """
        salt = self._get_salt()
        signature = self._signify(data=data, salt=salt, key=self._hasher.signing_key)

        return salt + signature

    def _unsign(self, parts: SignedDataParts) -> bytes:
        """Verify signed data parts and recover original data.

        Args:
            parts: Signed data parts to unsign.

        Returns:
            Original data.

        Raises:
            InvalidSignatureError: Signed data signature is invalid.
        """
        for key in reversed(self._hasher.keys):
            signature = self._signify(data=parts.data, salt=parts.salt, key=key)
            if compare_digest(signature, parts.signature):
                return parts.data

        raise InvalidSignatureError('signature is not valid')


class Blake2TimestampSignerBase(Blake2SignerBase, ABC):
    """Base class for a timestamp signer based on BLAKE in keyed hashing mode."""

    def _get_timestamp(self) -> bytes:
        """Get the encoded timestamp value."""
        timestamp = int(time())  # It's easier to encode and decode an integer
        try:
            timestamp_b = timestamp.to_bytes(4, 'big', signed=False)
        except OverflowError:  # This will happen in ~2106-02-07
            raise RuntimeError(
                'can not represent this timestamp in bytes: this library is '
                + 'too old and needs to be updated!',
            )

        return self._encode(timestamp_b)

    def _decode_timestamp(self, encoded_timestamp: bytes) -> int:
        """Decode an encoded timestamp whose signature should have been validated.

        Args:
            encoded_timestamp: encoded timestamp to decode.

        Returns:
            An integer timestamp.

        Raises:
            DecodeError: Timestamp can't be decoded.
        """
        return int.from_bytes(self._decode(encoded_timestamp), 'big', signed=False)

    def _compose_timestamp(self, data: bytes, *, timestamp: bytes) -> bytes:
        """Compose timestamp value with data."""
        return timestamp + self._separator + data

    def _decompose_timestamp(self, timestamped_data: bytes) -> TimestampedDataParts:
        """Decompose data + timestamp value.

        Args:
            timestamped_data: composed data with timestamp to decompose.

        Returns:
            A container with data and timestamp.

        Raises:
            SignatureError: Invalid timestamped data.
            DecodeError: Timestamp can't be decoded.
        """
        if self._separator not in timestamped_data:
            raise SignatureError('separator not found in timestamped data')

        encoded_timestamp, data = timestamped_data.split(self._separator, 1)

        if not encoded_timestamp:
            raise SignatureError('timestamp information is missing')

        timestamp = self._decode_timestamp(encoded_timestamp)

        return TimestampedDataParts(data=data, timestamp=timestamp)

    @staticmethod
    def _get_ttl_from_max_age(max_age: typing.Union[int, float, timedelta]) -> float:
        """Get the time-to-live value in seconds."""
        if isinstance(max_age, timedelta):
            return max_age.total_seconds()

        return float(max_age)

    def _sign_with_timestamp(self, data: bytes) -> bytes:
        """Sign given data and produce a timestamped signature stream.

        The timestamped signature stream (timestamp, signature and salt) is
        encoded using the chosen encoder.

        Args:
            data: data to sign.

        Returns:
            A signature stream composed of salt, signature and timestamp.
        """
        timestamp = self._get_timestamp()
        timestamped_data = self._compose_timestamp(data, timestamp=timestamp)

        return self._compose(timestamp, signature=self._sign(timestamped_data))

    def _unsign_with_timestamp(
        self,
        parts: SignedDataParts,
        *,
        max_age: typing.Union[None, int, float, timedelta],
    ) -> bytes:
        """Verify signed data parts with timestamp and recover original data.

        If `max_age` is not provided, then the timestamp is not checked (the
        signature is always checked).

        Args:
            parts: Signed data parts to unsign.

        Keyword Args:
            max_age (optional): Ensure the signature is not older than this time
                in seconds.

        Returns:
            Original data.

        Raises:
            SignatureError: Signed data structure is not valid.
            InvalidSignatureError: Signed data signature is invalid.
            ExpiredSignatureError: Signed data signature has expired.
            DecodeError: Timestamp can't be decoded.
        """
        timestamped_data = self._unsign(parts)

        timestamped_parts = self._decompose_timestamp(timestamped_data)

        if max_age is None:
            return timestamped_parts.data

        now = time()
        age = now - timestamped_parts.timestamp
        ttl = self._get_ttl_from_max_age(max_age)

        if age > ttl:
            raise ExpiredSignatureError(
                f'signature has expired, age {age} > {ttl} seconds',
                timestamp=timestamp_to_aware_datetime(timestamped_parts.timestamp),
            )

        if age < 0:  # Signed in the future
            raise ExpiredSignatureError(
                f'signature has expired, age {age} < 0 seconds',
                timestamp=timestamp_to_aware_datetime(timestamped_parts.timestamp),
            )

        return timestamped_parts.data


class Blake2DualSignerBase(Blake2TimestampSignerBase, ABC):
    """Base class for a dual signer: with and without timestamp."""

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
    ) -> None:
        """Sign and verify signed and optionally timestamped data using BLAKE.

        It uses BLAKE in keyed hashing mode.

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
            separator (optional): Character to separate the signature and the
                payload. It must not belong to the encoder alphabet and be ASCII
                (defaults to ".").
            encoder (optional): Encoder class to use (defaults to a Base64 URL
                safe encoder).

        Raises:
            ConversionError: A bytes parameter is not bytes and can't be converted
                to bytes.
            InvalidOptionError: A parameter is out of bounds.
        """
        if max_age is not None:
            personalisation = self._force_bytes(personalisation) + b'Timestamp'

        self._max_age: typing.Union[None, int, float, timedelta] = max_age

        super().__init__(
            secret,
            personalisation=personalisation,
            digest_size=digest_size,
            hasher=hasher,
            deterministic=deterministic,
            separator=separator,
            encoder=encoder,
        )

    def _proper_sign(self, data: bytes) -> bytes:
        """Sign given data with a (timestamp) signer producing a signature stream.

        The signature stream (salt, signature and/or timestamp) is encoded using
        the chosen encoder.

        Args:
            data: data to sign.

        Returns:
            A signature stream of the salt, signature, and timestamp, if corresponds.
        """
        if self._max_age is None:
            return self._sign(data)

        return self._sign_with_timestamp(data)

    def _proper_unsign(self, parts: SignedDataParts) -> bytes:
        """Unsign signed data properly with the corresponding signer.

        Args:
            parts: signed data parts to unsign.

        Returns:
            Original data.

        Raises:
            SignatureError: Signed data structure is not valid.
            InvalidSignatureError: Signed data signature is invalid.
            ExpiredSignatureError: Signed data signature has expired.
            DecodeError: Timestamp can't be decoded.
        """
        if self._max_age is None:
            return self._unsign(parts)

        return self._unsign_with_timestamp(parts, max_age=self._max_age)


class Blake2SerializerSignerBase(Blake2DualSignerBase, ABC):
    """Base class for a serializer signer that implements `dumps` and `loads`."""

    @abstractmethod
    def _dumps(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Dump data serializing it.

        Implement this method with all the tasks necessary to serialize data, such
        as encoding, compression, etc.

        Args:
            data: Data to serialize.

        Keyword Args:
            **kwargs: Additional keyword only arguments for the method.

        Returns:
            Serialized data.
        """

    @abstractmethod
    def _loads(self, dumped_data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Load serialized data to recover it.

        Implement this method with all the tasks necessary to unserialize data,
        such as decoding, decompression, etc.

        Args:
            dumped_data: Data to unserialize.

        Keyword Args
            **kwargs: Additional keyword only arguments for the method.

        Returns:
            Original data.
        """

    @staticmethod
    def _read(file: typing.IO) -> typing.AnyStr:
        """Read data from a file.

        Args:
            file: file to read data from.

        Returns:
            File contents.

        Raises:
            FileError: File can't be read.
        """
        try:
            return file.read()
        except OSError as exc:
            raise FileError('file can not be read') from exc

    def _write(self, file: typing.IO, data: str) -> None:
        """Write data to file.

        Args:
            file: file to write data to.
            data: data to write to the file.

        Notes:
            The file can be either in text or binary mode, therefore given data
            is properly converted before writing.

        Raises:
            FileError: File can't be written.
            ConversionError: Data can't be converted to bytes (can happen when
                file is in binary mode).
        """
        data_ = data if file_mode_is_text(file) else self._force_bytes(data)

        try:
            file.write(data_)
        except OSError as exc:
            raise FileError('file can not be written') from exc
