"""Signers: low level classes to sign data."""

import typing
from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from hashlib import blake2b
from hashlib import blake2s
from secrets import compare_digest
from secrets import token_bytes
from time import time

from .errors import DecodeError
from .errors import ExpiredSignatureError
from .errors import InvalidOptionError
from .errors import InvalidSignatureError
from .utils import force_bytes


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
    timestamp: bytes


class Blake2Options(typing.TypedDict):
    """Blake2 options."""

    key: bytes
    digest_size: int
    person: bytes


class Hashers_(Enum):
    """Hasher selection options."""

    blake2b = 'blake2b'
    blake2s = 'blake2s'


class Blake2SignerBase(ABC):
    """Base class for a signer based on Blake2 in keyed hashing mode."""

    __slots__ = (
        '_hasher',
        '_hasher_options',
    )

    Hashers = Hashers_

    MIN_KEY_SIZE: int = 16
    MIN_DIGEST_SIZE: int = 8

    def __init__(
        self,
        key: bytes,
        *,
        hasher: Hashers_ = Hashers.blake2b,
        digest_size: typing.Optional[int] = None,
        person: bytes = b'',
    ) -> None:
        """Sign and verify signed data using Blake2 in keyed hashing mode.

        :param key: Secret key for signing and verifying signed data. The minimum
                    key size is enforced to 16 bytes, and the maximum depends on
                    the chosen hasher.
        :param hasher: [optional] Hash function to use: blake2b (default) or blake2s.
        :param digest_size: [optional] Size of output signature (digest) in bytes
                            (defaults to maximum digest size of chosen function).
                            Bear in mind that a small digest size increases the
                            risk collision. I.e. if we used 1 byte as digest size,
                            an attacker would be able to correctly sign any payload
                            in around ~128 attempts or less without needing to
                            know the secret key. For this reason the minimum size
                            is enforced to 8 bytes.
        :param person: [optional] personalisation string to force the hash function
                       to produce different digests for the same input.

        :raise InvalidOptionError: A parameter is out of bounds.
        """
        self._hasher: typing.Union[typing.Type[blake2b], typing.Type[blake2s]]
        if hasher is self.Hashers.blake2b:
            self._hasher = blake2b
        else:
            self._hasher = blake2s

        key, person = force_bytes(key), force_bytes(person)

        if not (self.MIN_KEY_SIZE <= len(key) <= self._hasher.MAX_KEY_SIZE):
            raise InvalidOptionError(
                f'key length should be between {self.MIN_KEY_SIZE} and '
                f'{self._hasher.MAX_KEY_SIZE}',
            )

        if digest_size is None:
            digest_size = self._hasher.MAX_DIGEST_SIZE
        elif not (self.MIN_DIGEST_SIZE <= digest_size <= self._hasher.MAX_DIGEST_SIZE):
            raise InvalidOptionError(
                f'digest_size should be between {self.MIN_DIGEST_SIZE} and '
                f'{self._hasher.MAX_DIGEST_SIZE}',
            )

        self._hasher_options: Blake2Options = Blake2Options(
            key=key,
            person=person,
            digest_size=digest_size,
        )

        self._check_hasher_options()

    def _check_hasher_options(self) -> None:
        """Check hasher options to be valid."""
        try:
            self._hasher(**self._hasher_options)
        except ValueError as exc:
            raise InvalidOptionError(exc) from exc

    @property
    def salt_size(self) -> int:
        """Get the salt size."""
        return self._hasher.SALT_SIZE

    @property
    def signature_size(self) -> int:
        """Get the signature size/length."""
        return self._hasher_options['digest_size']

    def _generate_salt(self) -> bytes:
        """Generate a cryptographically secure pseudorandom salt."""
        return token_bytes(self.salt_size)

    @staticmethod
    def _compose(*, salt: bytes, signature: bytes, data: bytes) -> bytes:
        """Compose signed data parts into a single stream."""
        return salt + signature + data

    def _decompose(self, signed_data: bytes) -> SignedDataParts:
        """Decompose a signed data stream into its parts.

        :raise DecodeError: Invalid signed data.
        """
        if len(signed_data) < (self.salt_size + self.signature_size):
            raise DecodeError('signed data is too short')

        salt = signed_data[:self.salt_size]
        signature = signed_data[self.salt_size:self.salt_size + self.signature_size]
        data = signed_data[self.salt_size + self.signature_size:]

        return SignedDataParts(data=data, salt=salt, signature=signature)

    def _sign(self, *, salt: bytes, data: bytes) -> bytes:
        """Sign given data using salt and all of the hasher options."""
        signed_data = self._hasher(
            data,
            salt=salt,
            **self._hasher_options,
        ).digest()

        return signed_data

    def _verify(self, parts: SignedDataParts) -> bool:
        """Verify a signature.

        :return: True if the signature is correct, False otherwise.
        """
        good_signature = self._sign(salt=parts.salt, data=parts.data)

        return compare_digest(good_signature, parts.signature)

    def _unsign(self, signed_data: bytes) -> bytes:
        """Verify a signed stream and recover original data.

        :param signed_data: Signed data to unsign.

        :raise DecodeError: Signed data is not valid or it can't be decoded.
        :raise InvalidSignatureError: Signed data has invalid signature.

        :return: Original data.
        """
        parts = self._decompose(signed_data)
        if self._verify(parts):
            return parts.data

        raise InvalidSignatureError('signature is not valid')

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign given data and produce a stream."""


class Blake2Signer(Blake2SignerBase):
    """Blake2 in keyed hashing mode for signing data."""

    def sign(self, data: bytes) -> bytes:
        """Sign given data and produce a stream composed of it, salt and signature.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature, use `unsign`.

        The salt is a cryptographically secure pseudorandom string generated for
        this signature only.

        The total length of the resulting stream can be calculated as:
        len(data) + salt_size + signature_size.

        :return: A signed stream composed of data + salt + signature.
        """
        salt = self._generate_salt()
        data = force_bytes(data)
        signature = self._sign(salt=salt, data=data)

        return self._compose(salt=salt, signature=signature, data=data)

    def unsign(self, signed_data: bytes) -> bytes:
        """Verify a signed stream and recover original data.

        :param signed_data: Signed data to unsign.

        :raise DecodeError: Signed data is not valid or it can't be decoded.
        :raise InvalidSignatureError: Signed data has invalid signature.

        :return: Original data.
        """
        signed_data = force_bytes(signed_data)

        return self._unsign(signed_data)


class Blake2TimestampSigner(Blake2SignerBase):
    """Blake2 in keyed hashing mode for signing data with timestamp."""

    @property
    def timestamp_size(self) -> int:
        """Get the timestamp value size in bytes."""
        return 4  # Good enough until year 2106

    @property
    def timestamp(self) -> bytes:
        """Get the encoded timestamp value."""
        timestamp = int(time())  # its easier to encode an integer
        try:
            return timestamp.to_bytes(self.timestamp_size, 'big', signed=False)
        except OverflowError:  # This will happen in ~2106-02-07
            raise NotImplementedError(
                'can not represent this timestamp in bytes: this library is '
                'too old and needs to be updated!',
            )

    @staticmethod
    def _decode_timestamp(encoded_timestamp: bytes) -> int:
        """Decode an encoded timestamp which should have been validated."""
        timestamp = int.from_bytes(encoded_timestamp, 'big', signed=False)

        return timestamp

    def _add_timestamp(self, data: bytes) -> bytes:
        """Add timestamp value to given data."""
        return self.timestamp + data

    def _split_timestamp(self, timestamped_data: bytes) -> TimestampedDataParts:
        """Split data + timestamp value.

        :raise DecodeError: Invalid timestamped data.
        """
        if len(timestamped_data) < self.timestamp_size:
            raise DecodeError('timestamped data is too short')

        timestamp = timestamped_data[:self.timestamp_size]
        data = timestamped_data[self.timestamp_size:]

        return TimestampedDataParts(data=data, timestamp=timestamp)

    def sign(self, data: bytes) -> bytes:
        """Sign given data and produce a stream of it, timestamp, salt and signature.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature, use `unsign`.

        The salt is a cryptographically secure pseudorandom string generated for
        this signature only.

        The total length of the resulting stream can be calculated as:
        len(data) + timestamp_size + salt_size + signature_size.

        :return: A signed stream composed of data + timestamp + salt + signature.
        """
        salt = self._generate_salt()
        data = force_bytes(data)
        data_to_sign = self._add_timestamp(data)
        signature = self._sign(salt=salt, data=data_to_sign)
        return self._compose(salt=salt, signature=signature, data=data_to_sign)

    def unsign(
        self,
        signed_data: bytes,
        *,
        max_age: typing.Union[int, float, timedelta],
    ) -> bytes:
        """Verify a signed stream with timestamp and recover original data.

        :param signed_data: Signed data to unsign.
        :param max_age: Ensure the signature is not older than this time in seconds.

        :raise DecodeError: Signed data is not valid or it can't be decoded.
        :raise InvalidSignatureError: Signed data has invalid signature.
        :raise ExpiredSignatureError: Signed data has expired.

        :return: Original data.
        """
        signed_data = force_bytes(signed_data)

        data = self._unsign(signed_data)

        data_parts = self._split_timestamp(data)

        if isinstance(max_age, timedelta):
            ttl = max_age.total_seconds()
        else:
            ttl = float(max_age)

        now = time()
        timestamp = self._decode_timestamp(data_parts.timestamp)
        age = timestamp + ttl
        if age < now:
            raise ExpiredSignatureError('signed data has expired')

        return data_parts.data
