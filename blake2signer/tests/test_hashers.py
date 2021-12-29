"""Hashers tests."""

import typing
from abc import ABC
from abc import abstractmethod

import pytest

from .. import errors
from ..hashers import BLAKE2Hasher
from ..hashers import BLAKE3Hasher
from ..hashers import HasherChoice
from ..hashers import blake3

THasher = typing.TypeVar('THasher', BLAKE2Hasher, BLAKE3Hasher)


class BaseTests(typing.Generic[THasher], ABC):
    """Base class for the hashers' tests."""
    secret = b'0123456789012345'
    person = b'acab'
    digest_size = 16

    @property
    @abstractmethod
    def hasher_class(self) -> typing.Type[THasher]:
        """Get the hasher class to test."""

    @property
    @abstractmethod
    def hasher_choice(self) -> HasherChoice:
        """Get the default hasher choice."""

    def get_hasher(
        self,
        hasher: typing.Optional[HasherChoice] = None,
        *,
        secret: typing.Optional[bytes] = None,
        digest_size: typing.Optional[int] = None,
        person: typing.Optional[bytes] = None,
    ) -> THasher:
        """Get the hasher instance to test."""
        return self.hasher_class(
            hasher or self.hasher_choice,
            secret=secret or self.secret,
            digest_size=digest_size or self.digest_size,
            person=person or self.person,
        )


class TestsBLAKE2Hasher(BaseTests[BLAKE2Hasher]):
    """BLAKE2Hasher tests."""

    @property
    def hasher_class(self) -> typing.Type[BLAKE2Hasher]:
        """Get the hasher class to test."""
        return BLAKE2Hasher

    @property
    def hasher_choice(self) -> HasherChoice:
        """Get the hasher class to test."""
        return HasherChoice.blake2b

    @pytest.mark.parametrize(
        'choice',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
        ),
    )
    def test_validate_digest_size_too_long(self, choice: HasherChoice) -> None:
        """Test that digest_size is being correctly validated."""
        with pytest.raises(
                errors.InvalidOptionError,
                match='digest_size should be lower',
        ):
            self.get_hasher(choice, digest_size=128)

    @pytest.mark.parametrize(
        'choice',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
        ),
    )
    def test_derive_person(self, choice: HasherChoice) -> None:
        """Test that person is correctly derived."""
        hasher = self.get_hasher(choice)

        assert self.person != hasher._person
        assert hasher._hasher.PERSON_SIZE == len(hasher._person)

    @pytest.mark.parametrize(
        'choice',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
        ),
    )
    def test_derive_secret(self, choice: HasherChoice) -> None:
        """Test that secret is correctly derived."""
        hasher = self.get_hasher(choice)

        assert self.secret != hasher._key
        assert hasher._hasher.MAX_KEY_SIZE == len(hasher._key)

    @pytest.mark.parametrize(
        ('choice', 'data', 'salt', 'expected_digest'),
        (
            (
                HasherChoice.blake2b,
                b'datadata',
                b'',
                b'I\xb5v\x9d\xd7"\xec\xd8Q\x0c\x94\xd0\xa1\x02z?',
            ),
            (
                HasherChoice.blake2b,
                b'datadata',
                b'salt',
                b'\xb8\xa4\x84o\xbf\xf6>\xc1\x9dLN/\xbe\\\xd1>',
            ),
            (
                HasherChoice.blake2s,
                b'datadata',
                b'',
                b"\xf9`<\x8c\x85\xe8o+\x07'\x84s=\xc5'\x8a",
            ),
            (
                HasherChoice.blake2s,
                b'datadata',
                b'salt',
                b'\xfb,T\xc0\xc5\xf5\xf4\xf9\xfc\x8d\xb1T\xceY\x03\xdb',
            ),
        ),
    )
    def test_digest(
        self,
        choice: HasherChoice,
        data: bytes,
        salt: bytes,
        expected_digest: bytes,
    ) -> None:
        """Test that digest is correctly calculated."""
        hasher = self.get_hasher(choice)

        digest = hasher.digest(b'datadata', salt=salt)

        assert expected_digest == digest


class TestsBLAKE3Hasher(BaseTests[BLAKE3Hasher]):
    """BLAKE3Hasher tests."""

    @property
    def hasher_class(self) -> typing.Type[BLAKE3Hasher]:
        """Get the hasher class to test."""
        return BLAKE3Hasher

    @property
    def hasher_choice(self) -> HasherChoice:
        """Get the hasher class to test."""
        return HasherChoice.blake3

    def test_validate_digest_size_unlimited(self) -> None:
        """Test that blake3 has no maximum digest size."""
        hasher = self.get_hasher(digest_size=1_000)

        assert hasher.max_digest_size is None

    def test_derive_person(self) -> None:
        """Test that person is not derived."""
        hasher = self.get_hasher()

        assert self.person == hasher._person

    def test_derive_secret(self) -> None:
        """Test that secret is correctly derived."""
        hasher = self.get_hasher()

        assert self.secret != hasher._key
        assert blake3().key_size == len(hasher._key)

    @pytest.mark.parametrize(
        ('data', 'salt', 'expected_digest'),
        (
            (b'datadata', b'', b"\xfe\x88\x96\xe5\xdf:\xb6f\xe1}\x9f\x18\x9a'\xad\x8d"),
            (b'datadata', b'salt', b'\xeez6\xf20\xca\xcae\x93\xc3\xcchh\x90(\xdf'),
        ),
    )
    def test_digest(
        self,
        data: bytes,
        salt: bytes,
        expected_digest: bytes,
    ) -> None:
        """Test that digest is correctly calculated."""
        hasher = self.get_hasher()

        digest = hasher.digest(b'datadata', salt=salt)

        assert expected_digest == digest
