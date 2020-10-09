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

from . import errors
from .utils import b64decode
from .utils import b64encode
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

    Hashers = Hashers_

    MIN_SECRET_SIZE: int = 16
    MIN_DIGEST_SIZE: int = 16

    SEPARATOR: bytes = b'.'  # ascii non-base64 ([a-zA-Z0-9-_=]) symbol!

    def __init__(
        self,
        secret: bytes,
        *,
        personalisation: bytes = b'',
        digest_size: typing.Optional[int] = None,
        hasher: Hashers_ = Hashers.blake2b,
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

        :raise ConversionError: A parameter is not bytes and can't be converted
                                to bytes.
        :raise InvalidOptionError: A parameter is out of bounds.
        """
        self._hasher: typing.Union[typing.Type[blake2b], typing.Type[blake2s]]
        self._hasher = blake2b if hasher is self.Hashers.blake2b else blake2s

        secret = self._force_bytes(secret)
        person = self._force_bytes(personalisation)

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

        self._digest_size = digest_size
        self._person = self._derive_person(person + self.__class__.__name__.encode())
        self._key = self._derive_key(secret, person=self._person)  # forget secret :)

    @property
    def _salt_size(self) -> int:
        """Get the salt size."""
        return self._hasher.SALT_SIZE

    @property
    def _hasher_options(self) -> Blake2Options:
        """Get the required options for the hasher."""
        return Blake2Options(
            key=self._key,
            person=self._person,
            digest_size=self._digest_size,
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
        # bits but it's OK since we are using the maximum allowed size..
        return token_urlsafe(self._salt_size).encode()[:self._salt_size]  # Trim excess

    @staticmethod
    def _force_bytes(value: typing.AnyStr) -> bytes:
        """Force given value into bytes.

        :raise ConversionError: Can't force value into bytes.
        """
        try:
            return force_bytes(value)
        except Exception:
            raise errors.ConversionError('value can not be converted to bytes')

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
        """Sign given data and produce a stream composed of it, salt and signature.

        The signature and salt are base64 URL safe encoded without padding.
        Data is left as-is.
        """
        salt = self._generate_salt()
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
            raise errors.SignatureError('timestamp can not be decoded')

    def _add_timestamp(self, data: bytes) -> bytes:
        """Add timestamp value to given data."""
        return self._get_timestamp() + self.SEPARATOR + data

    def _split_timestamp(self, timestamped_data: bytes) -> TimestampedDataParts:
        """Split data + timestamp value.

        :raise SignatureError: Invalid timestamped data.
        """
        if self.SEPARATOR not in timestamped_data:
            raise errors.SignatureError('separator not found in timestamped data')

        timestamp, data = timestamped_data.split(self.SEPARATOR, 1)

        if not timestamp:
            raise errors.SignatureError('timestamp information is missing')

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

        data_parts = self._split_timestamp(data)

        now = time()
        timestamp = self._decode_timestamp(data_parts.timestamp)
        age = now - timestamp
        ttl = self._get_ttl_from_max_age(max_age)
        if age > ttl:
            raise errors.ExpiredSignatureError('signature has expired')

        return data_parts.data


class Blake2Signer(Blake2SignerBase):
    """Blake2 in keyed hashing mode for signing data."""

    def sign(self, data: typing.AnyStr) -> bytes:
        """Sign given data and produce a stream composed of it, salt and signature.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature, use :meth:`unsign`.

        The signature and salt are base64 URL safe encoded without padding.
        Data is left as-is.

        The salt is a cryptographically secure pseudorandom string generated for
        this signature only.

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
    """Blake2 in keyed hashing mode for signing data with timestamp."""

    def sign(self, data: typing.AnyStr) -> bytes:
        """Sign given data and produce a stream of it, timestamp, salt and signature.

        Note that given data is _not_ encrypted, only signed. To recover data from
        it, while validating the signature and timestamp, use :meth:`unsign`.

        The signature, salt and timestamp are base64 URL safe encoded without
        padding. Data is left as-is.

        The salt is a cryptographically secure pseudorandom string generated for
        this signature only.

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
