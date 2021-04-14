"""Bases: base classes for signers."""

import hashlib
import typing
from abc import ABC
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from secrets import compare_digest
from secrets import token_urlsafe
from time import time

from . import errors
from .mixins import Mixin
from .utils import b64decode
from .utils import b64encode


@dataclass(frozen=True)
class SignedDataParts:
    """Parts of a signed data container."""

    data: bytes
    salt: bytes
    signature: bytes


@dataclass(frozen=True)
class TimestampedDataParts:
    """Parts of a timestamped data container."""

    data: bytes
    timestamp: int


class HasherChoice(str, Enum):
    """Hasher selection choices."""

    blake2b = 'blake2b'
    blake2s = 'blake2s'


class Blake2SignerBase(Mixin, ABC):
    """Base class for a signer based on Blake2 in keyed hashing mode."""

    Hashers = HasherChoice  # Sugar to avoid having to import the enum

    MIN_SECRET_SIZE: int = 16  # Minimum secret size allowed (during instantiation)
    MIN_DIGEST_SIZE: int = 16  # Minimum digest size allowed (during instantiation)

    SEPARATOR: bytes = b'.'  # ascii non-base64 ([a-zA-Z0-9-_=]) symbol!

    def __init__(
        self,
        secret: bytes,
        *,
        personalisation: bytes = b'',
        digest_size: typing.Optional[int] = None,
        hasher: typing.Union[HasherChoice, str] = Hashers.blake2b,
        deterministic: bool = False,
    ) -> None:
        """Sign and verify signed data using Blake2 in keyed hashing mode.

        :param secret: Secret value which will be derived using blake2 to
                       produce the signing key. The minimum secret size is
                       enforced to 16 bytes and there is no maximum since the key
                       will be derived to the maximum supported size.
        :param digest_size: [optional] Size of output signature (digest) in bytes
                            (defaults to maximum digest size of chosen function).
                            The minimum size is enforced to 16 bytes.
        :param personalisation: [optional] Personalisation string to force the
                                hash function to produce different digests for
                                the same input. It is derived using blake2 to ensure
                                it fits the hasher limits, so it has no practical
                                size limit. It defaults to the class name.
        :param hasher: [optional] Hash function to use: blake2b (default) or blake2s.
        :param deterministic: [optional] Define if signatures are deterministic
                              or non-deterministic (default). Non-deterministic
                              sigs are preferred, and achieved through the use of a
                              random salt. For deterministic sigs, no salt is used:
                              this means that for the same payload, the same sig is
                              obtained (the advantage is that the sig is shorter).

        :raise ConversionError: A parameter is not bytes and can't be converted
                                to bytes.
        :raise InvalidOptionError: A parameter is out of bounds.
        """
        self._hasher: typing.Union[
            typing.Type[hashlib.blake2b],
            typing.Type[hashlib.blake2s],
        ]
        self._hasher = self._choose_hasher(hasher)

        secret = self._force_bytes(secret)
        person = self._force_bytes(personalisation)
        if deterministic:
            person += b'Deterministic'

        if len(secret) < self.MIN_SECRET_SIZE:
            raise errors.InvalidOptionError(
                f'secret should be longer than {self.MIN_SECRET_SIZE} bytes',
            )

        if digest_size is None:
            digest_size = self._hasher.MAX_DIGEST_SIZE
        elif not (self.MIN_DIGEST_SIZE <= digest_size <= self._hasher.MAX_DIGEST_SIZE):
            raise errors.InvalidOptionError(
                f'digest_size should be between {self.MIN_DIGEST_SIZE} and '
                f'{self._hasher.MAX_DIGEST_SIZE}',
            )

        self._deterministic = deterministic
        self._digest_size = digest_size
        self._person = self._derive_person(person + self.__class__.__name__.encode())
        self._key = self._derive_key(secret, person=self._person)  # forget secret :)

    @property
    def _salt_size(self) -> int:
        """Get the salt size."""
        return self._hasher.SALT_SIZE

    def _choose_hasher(
        self,
        hasher: typing.Union[HasherChoice, str],
    ) -> typing.Union[typing.Type[hashlib.blake2b], typing.Type[hashlib.blake2s]]:
        """Choose hashing function."""
        if hasher == self.Hashers.blake2b:
            return hashlib.blake2b
        elif hasher == self.Hashers.blake2s:
            return hashlib.blake2s

        raise errors.InvalidOptionError(
            f'invalid hasher choice, must be one of: '
            f'{", ".join(h for h in self.Hashers)}',
        )

    def _derive_person(self, person: bytes) -> bytes:
        """Derive given personalisation value to ensure it fits the hasher correctly."""
        return self._hasher(person, digest_size=self._hasher.PERSON_SIZE).digest()

    def _derive_key(self, secret: bytes, *, person: bytes = b'') -> bytes:
        """Derive given secret to ensure it fits correctly as the hasher key."""
        return self._hasher(
            secret,
            person=person,
            digest_size=self._hasher.MAX_KEY_SIZE,
        ).digest()

    def _generate_salt(self) -> bytes:
        """Generate a cryptographically secure pseudorandom salt."""
        # Generate an encoded salt to use it as is so we don't have to deal with
        # decoding it when unsigning. The only downside is that we loose a few
        # bits but it's OK since we are using the maximum allowed size.
        return token_urlsafe(self._salt_size).encode()[:self._salt_size]  # Trim excess

    def _get_salt(self) -> bytes:
        """Get a salt for the signature considering its type.

        For non-deterministic signatures, a pseudo random salt is generated.
        """
        return b'' if self._deterministic else self._generate_salt()

    def _compose(self, parts: SignedDataParts) -> bytes:
        """Compose signed data parts into a single stream."""
        return parts.salt + parts.signature + self.SEPARATOR + parts.data

    def _decompose(self, signed_data: bytes) -> SignedDataParts:
        """Decompose a signed data stream into its parts.

        :raise SignatureError: Invalid signed data.
        """
        if self.SEPARATOR not in signed_data:
            raise errors.SignatureError('separator not found in signed data')

        composite_signature, data = signed_data.split(self.SEPARATOR, 1)

        if self._deterministic:
            salt = b''
            signature = composite_signature
        else:
            if len(composite_signature) < (self._salt_size + self.MIN_DIGEST_SIZE):
                raise errors.SignatureError('signature is too short')

            salt = composite_signature[:self._salt_size]
            signature = composite_signature[self._salt_size:]

        return SignedDataParts(data=data, salt=salt, signature=signature)

    def _signify(self, *, salt: bytes, data: bytes) -> bytes:
        """Return signature for given data using salt and all of the hasher options.

        The signature is base64 URL safe encoded.
        """
        signature = self._hasher(
            data,
            salt=salt,
            key=self._key,
            person=self._person,
            digest_size=self._digest_size,
        ).digest()

        return b64encode(signature)

    def _verify(self, parts: SignedDataParts) -> bool:
        """Verify a signature for given data and salt.

        :return: True if the signature is correct, False otherwise.
        """
        good_signature = self._signify(salt=parts.salt, data=parts.data)

        return compare_digest(good_signature, parts.signature)

    def _sign(self, data: bytes) -> bytes:
        """Sign given data and produce a stream composed of it, salt and signature.

        The signature and salt are base64 URL safe encoded without padding.
        Data is left as-is.
        """
        salt = self._get_salt()
        signature = self._signify(salt=salt, data=data)
        parts = SignedDataParts(salt=salt, signature=signature, data=data)

        return self._compose(parts)

    def _unsign(self, signed_data: bytes) -> bytes:
        """Verify a signed stream and recover original data.

        :param signed_data: Signed data to unsign.

        :raise SignatureError: Signed data structure is not valid.
        :raise InvalidSignatureError: Signed data signature is invalid.

        :return: Original data.
        """
        parts = self._decompose(signed_data)
        if self._verify(parts):
            return parts.data

        raise errors.InvalidSignatureError('signature is not valid')


class Blake2TimestampSignerBase(Blake2SignerBase, ABC):
    """Base class for a timestamp signer based on Blake2 in keyed hashing mode."""

    @staticmethod
    def _get_timestamp() -> bytes:
        """Get the encoded timestamp value."""
        timestamp = int(time())  # its easier to encode and decode an integer
        try:
            timestamp_b = timestamp.to_bytes(4, 'big', signed=False)
        except OverflowError:  # This will happen in ~2106-02-07
            raise RuntimeError(
                'can not represent this timestamp in bytes: this library is '
                'too old and needs to be updated!',
            )

        return b64encode(timestamp_b)

    @staticmethod
    def _decode_timestamp(encoded_timestamp: bytes) -> int:
        """Decode an encoded timestamp whose signature should have been validated.

        :raise DecodeError: timestamp can't be decoded.
        """
        try:
            return int.from_bytes(b64decode(encoded_timestamp), 'big', signed=False)
        except Exception:
            raise errors.DecodeError('timestamp can not be decoded')

    def _add_timestamp(self, data: bytes) -> bytes:
        """Add timestamp value to given data."""
        return self._get_timestamp() + self.SEPARATOR + data

    def _split_timestamp(self, timestamped_data: bytes) -> TimestampedDataParts:
        """Split data + timestamp value.

        :raise SignatureError: Invalid timestamped data.
        """
        if self.SEPARATOR not in timestamped_data:
            raise errors.SignatureError('separator not found in timestamped data')

        encoded_timestamp, data = timestamped_data.split(self.SEPARATOR, 1)

        if not encoded_timestamp:
            raise errors.SignatureError('timestamp information is missing')

        timestamp = self._decode_timestamp(encoded_timestamp)

        return TimestampedDataParts(data=data, timestamp=timestamp)

    @staticmethod
    def _get_ttl_from_max_age(max_age: typing.Union[int, float, timedelta]) -> float:
        """Get the time-to-live value in seconds."""
        if isinstance(max_age, timedelta):
            return max_age.total_seconds()

        return float(max_age)

    def _sign_with_timestamp(self, data: bytes) -> bytes:
        """Sign given data and produce a stream of it, timestamp, salt and signature.

        The signature, salt and timestamp are base64 URL safe encoded without
        padding. Data is left as-is.

        :return: A signed stream composed of salt, signature, timestamp and data.
        """
        timestamped_data = self._add_timestamp(self._force_bytes(data))

        return self._sign(timestamped_data)

    def _unsign_with_timestamp(
        self,
        signed_data: bytes,
        *,
        max_age: typing.Union[int, float, timedelta],
    ) -> bytes:
        """Verify a stream signed and timestamped and recover data.

        :param signed_data: Signed data to unsign.
        :param max_age: Ensure the signature is not older than this time in seconds.

        :raise SignatureError: Signed data structure is not valid.
        :raise InvalidSignatureError: Signed data signature is invalid.
        :raise ExpiredSignatureError: Signed data signature has expired.

        :return: Original data.
        """
        data = self._unsign(signed_data)

        parts = self._split_timestamp(data)

        now = time()
        age = now - parts.timestamp
        ttl = self._get_ttl_from_max_age(max_age)
        if age > ttl:
            raise errors.ExpiredSignatureError('signature has expired')

        return parts.data


class Blake2SerializerSignerBase(Blake2TimestampSignerBase, ABC):
    """Base class for a serializer signer that implements `dumps` and `loads`."""

    DEFAULT_DIGEST_SIZE: int = 16  # 16 bytes is good security/size tradeoff

    def __init__(
        self,
        secret: bytes,
        *,
        max_age: typing.Union[None, int, float, timedelta] = None,
        personalisation: bytes = b'',
        digest_size: typing.Optional[int] = None,
        hasher: typing.Union[HasherChoice, str] = HasherChoice.blake2b,
        deterministic: bool = False,
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
        :param deterministic: [optional] Define if signatures are deterministic
                              or non-deterministic (default). Non-deterministic
                              sigs are preferred, and achieved through the use of a
                              random salt. For deterministic sigs, no salt is used:
                              this means that for the same payload, the same sig is
                              obtained (the advantage is that the sig is shorter).

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
            deterministic=deterministic,
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
