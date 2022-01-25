"""BLAKE hashers handlers."""

import hashlib
import typing
from abc import ABC
from abc import abstractmethod
from enum import Enum

from blake2signer import errors
from .blake3_package import blake3


class HasherChoice(str, Enum):
    """Hasher selection choices."""

    blake2b = 'blake2b'
    blake2s = 'blake2s'
    blake3 = 'blake3'


class BLAKEHasher(ABC):
    """BLAKE interface to manage payload signing using different BLAKE versions."""

    def __init__(
        self,
        hasher: HasherChoice,
        *,
        secrets: typing.Tuple[bytes, ...],
        digest_size: int,
        person: bytes,
    ) -> None:
        """BLAKE hasher to interface with different BLAKE versions.

        Args:
            hasher: Hash function to use.

        Keyword Args:
            secrets: A tuple of secret values which are derived using BLAKE to produce
                the signing key, to ensure they fit the hasher limits (so they have
                no practical size limit), from oldest to newest. This allows secret
                rotation: signatures are checked against all of them, but the last one
                (the newest one) is used to sign.
            digest_size: Size of digest in bytes.
            person: Personalisation string to force the hash function to produce
                different digests for the same input. It is derived using BLAKE to
                ensure it fits the hasher limits, so it has no practical size limit.

        Raises:
            InvalidOptionError: A parameter is out of bounds.
            MissingDependencyError: A required dependency is not met.
        """
        # I'm purposefully omitting further validation of this hasher choice, because
        # that is handled by the signer, which is also responsible for casting a
        # BLAKE2Hasher or BLAKE3Hasher correspondingly.
        self._hasher_choice = hasher
        self._digest_size = self._validate_digest_size(digest_size)
        self._person = self._derive_person(person)
        self._keys = self._derive_keys(secrets, person=self._person)

    @property
    def keys(self) -> typing.Tuple[bytes, ...]:
        """Get hasher keys, from oldest to newest."""
        return self._keys

    @property
    def signing_key(self) -> bytes:
        """Get the hasher signing key (the newest one)."""
        return self._keys[-1]

    def _validate_digest_size(self, digest_size: int) -> int:
        """Validate the digest_size value and return it clean.

        Args:
            digest_size: digest size to validate.

        Returns:
            Validated digest size.

        Raises:
            InvalidOptionError: The value is out of bounds.
        """
        max_digest_size = self.max_digest_size
        if max_digest_size is not None and digest_size > max_digest_size:
            raise errors.InvalidOptionError(
                f'digest_size should be lower than or equal to {max_digest_size}',
            )

        return digest_size

    @property
    @abstractmethod
    def salt_size(self) -> int:
        """Get the salt size of the hasher."""

    @property
    @abstractmethod
    def max_digest_size(self) -> typing.Optional[int]:
        """Get the maximum digest size of the hasher, if any."""

    @abstractmethod
    def _derive_person(self, person: bytes) -> bytes:
        """Derive given personalisation value to ensure it fits the hasher correctly."""

    @abstractmethod
    def _derive_key(
        self,
        secret: bytes,
        *,
        person: bytes,
    ) -> bytes:
        """Derive hasher key from given secret to ensure it fits the hasher correctly."""

    def _derive_keys(
        self,
        secrets: typing.Tuple[bytes, ...],
        *,
        person: bytes,
    ) -> typing.Tuple[bytes, ...]:
        """Derive hasher keys from given secrets to ensure they fit the hasher."""
        return tuple(self._derive_key(secret, person=person) for secret in secrets)

    @abstractmethod
    def digest(
        self,
        data: bytes,
        *,
        key: bytes,
        salt: bytes,
    ) -> bytes:
        """Get a hash digest using the hasher in keyed hashing mode."""


class BLAKE2Hasher(BLAKEHasher):
    """Hasher interface with BLAKE2."""

    def __init__(
        self,
        hasher: HasherChoice,
        *,
        secrets: typing.Tuple[bytes, ...],
        digest_size: int,
        person: bytes,
    ) -> None:
        """BLAKE hasher to interface with different BLAKE versions.

        Args:
            hasher: Hash function to use.

        Keyword Args:
            secrets: A tuple of secret values which are derived using BLAKE to produce
                the signing key, to ensure they fit the hasher limits (so they have
                no practical size limit), from oldest to newest. This allows secret
                rotation: signatures are checked against all of them, but the last one
                (the newest one) is used to sign.
            digest_size: Size of digest in bytes.
            person: Personalisation string to force the hash function to produce
                different digests for the same input. It is derived using BLAKE to
                ensure it fits the hasher limits, so it has no practical size limit.

        Raises:
            InvalidOptionError: A parameter is out of bounds.
        """
        self._hasher: typing.Type[typing.Union[hashlib.blake2b, hashlib.blake2s]]
        self._hasher = getattr(hashlib, hasher)

        super().__init__(hasher, secrets=secrets, digest_size=digest_size, person=person)

    @property
    def salt_size(self) -> int:
        """Get the salt size of the hasher."""
        return self._hasher.SALT_SIZE

    @property
    def max_digest_size(self) -> typing.Optional[int]:
        """Get the maximum digest size, if any."""
        return self._hasher.MAX_DIGEST_SIZE

    def _derive_person(self, person: bytes) -> bytes:
        """Derive given personalisation value to ensure it fits the hasher correctly."""
        return self._hasher(person, digest_size=self._hasher.PERSON_SIZE).digest()

    def _derive_key(
        self,
        secret: bytes,
        *,
        person: bytes,
    ) -> bytes:
        """Derive hasher key from given secret to ensure it fits the hasher correctly."""
        return self._hasher(
            secret,
            digest_size=self._hasher.MAX_KEY_SIZE,
            person=person,
        ).digest()

    def digest(
        self,
        data: bytes,
        *,
        key: bytes,
        salt: bytes,
    ) -> bytes:
        """Get a hash digest using the hasher in keyed hashing mode."""
        return self._hasher(
            data,
            digest_size=self._digest_size,
            key=key,
            salt=salt,
            person=self._person,
        ).digest()


class BLAKE3Hasher(BLAKEHasher):
    """Hasher interface with BLAKE3."""

    @property
    def salt_size(self) -> int:
        """Get the salt size of the hasher."""
        return 16  # Arbitrary as there is no salt in BLAKE3, so use the same as blake2b

    @property
    def max_digest_size(self) -> typing.Optional[int]:
        """Get the maximum digest size of the hasher, if any."""
        return None

    def _derive_person(self, person: bytes) -> bytes:
        """Derive given personalisation value to ensure it fits the hasher correctly."""
        return person  # No need for deriving, BLAKE3 doesn't have this "person" concept

    def _derive_key(
        self,
        secret: bytes,
        *,
        person: bytes,
    ) -> bytes:
        """Derive hasher key from given secret to ensure it fits the hasher correctly."""
        # A side effect of this method is that it is called during the class
        # instantiation, and if the `blake3` package is not installed, will raise a
        # proper exception. However, should this not be called during instantiation,
        # then the exception will be raised further at `self.digest(...)`, which could
        # be unexpected, or worst, captured and swallowed by a try/except block for
        # signing/unsigning, which is why I leave this note here: if this method is no
        # longer called during init, add a check then to ensure that we raise the
        # exception there and not further (there's a test for this anyway).
        ctx = 'blake2signer 2021-12-29 18:04:37 BLAKE3Hasher key derivation'
        hasher = blake3(secret, derive_key_context=ctx)
        hasher.update(person)

        return hasher.digest(length=hasher.key_size)

    def digest(
        self,
        data: bytes,
        *,
        key: bytes,
        salt: bytes,
    ) -> bytes:
        """Get a hash digest using the hasher in keyed hashing mode."""
        # BLAKE3 doesn't support salt nor personalisation, so there are a few
        # options to consider. Check following snippet:
        # https://gitlab.com/hackancuba/blake2signer/-/snippets/2132545
        payload = salt + self._person + data
        hasher = blake3(payload, key=key)

        return hasher.digest(length=self._digest_size)
