"""Signers: low level classes to sign data."""

import typing
from abc import ABC
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from hashlib import blake2b
from hashlib import blake2s
from secrets import compare_digest
from secrets import token_urlsafe
from time import time

from .errors import DecodeError
from .errors import ExpiredSignatureError
from .errors import InvalidOptionError
from .errors import InvalidSignatureError
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

    SEPARATOR: bytes = b'.'  # ascii non-base64 ([a-zA-Z0-9-_=]) symbol!

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
        self._hasher = blake2b if hasher is self.Hashers.blake2b else blake2s

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

    def _generate_salt(self) -> bytes:
        """Generate a cryptographically secure pseudorandom salt."""
        # Generate an encoded salt to use it as is so we don't have to deal with
        # decoding it when unsigning. The only downside is that we loose a few
        # bits but it's OK since we are using the maximum allowed size..
        return token_urlsafe(self.salt_size).encode()[:self.salt_size]  # Trim excess

    def _compose(self, parts: SignedDataParts) -> bytes:
        """Compose signed data parts into a single stream."""
        return parts.salt + parts.signature + self.SEPARATOR + parts.data

    def _decompose(self, signed_data: bytes) -> SignedDataParts:
        """Decompose a signed data stream into its parts.

        :raise DecodeError: Invalid signed data.
        """
        if self.SEPARATOR not in signed_data:
            raise DecodeError('separator not found in signed data')

        composite_signature, data = signed_data.split(self.SEPARATOR, 1)

        if len(composite_signature) < (self.salt_size + self.MIN_DIGEST_SIZE):
            raise DecodeError('signature is too short')

        salt = composite_signature[:self.salt_size]
        signature = composite_signature[self.salt_size:]

        return SignedDataParts(data=data, salt=salt, signature=signature)

    def _signify(self, *, salt: bytes, data: bytes) -> bytes:
        """Return signature for given data using salt and all of the hasher options.

        The signature is base64 URL safe encoded.
        """
        signature = self._hasher(
            data,
            salt=salt,
            **self._hasher_options,
        ).digest()

        return b64encode(signature)

    def _verify(self, parts: SignedDataParts) -> bool:
        """Verify a signature for given data and salt.

        :return: True if the signature is correct, False otherwise.
        """
        good_signature = self._signify(salt=parts.salt, data=parts.data)

        return compare_digest(good_signature, parts.signature)

    def _sign(self, data: bytes) -> bytes:
        """Sign given data and produce a stream composed of it, salt and signature."""
        salt = self._generate_salt()
        signature = self._signify(salt=salt, data=data)
        parts = SignedDataParts(salt=salt, signature=signature, data=data)

        return self._compose(parts)

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


class Blake2Signer(Blake2SignerBase):
    """Blake2 in keyed hashing mode for signing data."""

    def sign(self, data: bytes) -> bytes:
        """Sign given data and produce a stream composed of it, salt and signature.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature, use :meth:`unsign`.

        The signature and salt are base64 URL safe encoded without padding.
        Data is left as-is.

        The salt is a cryptographically secure pseudorandom string generated for
        this signature only.

        :return: A signed stream composed of salt, signature and data.
        """
        return self._sign(data)

    def unsign(self, signed_data: bytes) -> bytes:
        """Verify a stream signed by :meth:`sign` and recover original data.

        :param signed_data: Signed data to unsign.

        :raise DecodeError: Signed data is not valid or it can't be decoded.
        :raise InvalidSignatureError: Signed data has invalid signature.

        :return: Original data.
        """
        return self._unsign(signed_data)


class Blake2TimestampSigner(Blake2SignerBase):
    """Blake2 in keyed hashing mode for signing data with timestamp."""

    @property
    def timestamp(self) -> bytes:
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
        """Decode an encoded timestamp whose signature should have been validated."""
        try:
            return int.from_bytes(b64decode(encoded_timestamp), 'big', signed=False)
        except Exception:
            raise DecodeError('encoded timestamp is not valid')

    def _add_timestamp(self, data: bytes) -> bytes:
        """Add timestamp value to given data."""
        return self.timestamp + self.SEPARATOR + data

    def _split_timestamp(self, timestamped_data: bytes) -> TimestampedDataParts:
        """Split data + timestamp value.

        :raise DecodeError: Invalid timestamped data.
        """
        if self.SEPARATOR not in timestamped_data:
            raise DecodeError('separator not found in timestamped data')

        timestamp, data = timestamped_data.split(self.SEPARATOR, 1)

        if not timestamp:
            raise DecodeError('timestamp information is missing')

        return TimestampedDataParts(data=data, timestamp=timestamp)

    def sign(self, data: bytes) -> bytes:
        """Sign given data and produce a stream of it, timestamp, salt and signature.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature, use :meth:`unsign`.

        The signature, salt and timestamp are base64 URL safe encoded without
        padding. Data is left as-is.

        The salt is a cryptographically secure pseudorandom string generated for
        this signature only.

        :return: A signed stream composed of salt, signature, timestamp and data.
        """
        timestamped_data = self._add_timestamp(data)

        return self._sign(timestamped_data)

    def unsign(
        self,
        signed_data: bytes,
        *,
        max_age: typing.Union[int, float, timedelta],
    ) -> bytes:
        """Verify a stream signed and timestamped by :meth:`sign` and recover data.

        :param signed_data: Signed data to unsign.
        :param max_age: Ensure the signature is not older than this time in seconds.

        :raise DecodeError: Signed data is not valid or it can't be decoded.
        :raise InvalidSignatureError: Signed data has invalid signature.
        :raise ExpiredSignatureError: Signed data has expired.

        :return: Original data.
        """
        data = self._unsign(signed_data)

        data_parts = self._split_timestamp(data)

        if isinstance(max_age, timedelta):
            ttl = max_age.total_seconds()
        else:
            ttl = float(max_age)

        now = time()
        timestamp = self._decode_timestamp(data_parts.timestamp)
        age = now - timestamp
        if age > ttl:
            raise ExpiredSignatureError('signed data has expired')

        return data_parts.data
