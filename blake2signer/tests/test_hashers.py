"""Hashers tests."""

import typing
from abc import ABC
from abc import abstractmethod
from unittest import mock

import pytest

from .. import errors
from ..hashers import BLAKE2Hasher
from ..hashers import BLAKE3Hasher
from ..hashers import HasherChoice
from ..hashers import blake3

THasher = typing.TypeVar('THasher', BLAKE2Hasher, BLAKE3Hasher)


class BaseTests(typing.Generic[THasher], ABC):
    """Base class for the hashers' tests."""
    secrets = (b'averysecretsecret', b'0123456789012345')
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
        secrets: typing.Optional[typing.Tuple[bytes]] = None,
        digest_size: typing.Optional[int] = None,
        person: typing.Optional[bytes] = None,
    ) -> THasher:
        """Get the hasher instance to test."""
        return self.hasher_class(
            hasher or self.hasher_choice,
            secrets=secrets or self.secrets,
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
        """Test that secrets are correctly derived."""
        hasher = self.get_hasher(choice)

        assert len(self.secrets) == len(hasher.keys)
        assert self.secrets != hasher.keys
        assert sorted(self.secrets) != sorted(hasher.keys)

        for key in hasher.keys:
            assert hasher._hasher.MAX_KEY_SIZE == len(key)

        # Ensure keys are actually derived
        with mock.patch.object(self.hasher_class, '_derive_key') as mock_derive_key:
            hasher = self.get_hasher(choice)
        calls = []
        for secret in self.secrets:
            calls.append(mock.call(secret, person=hasher._person))
        mock_derive_key.assert_has_calls(calls)

        # Ensure the hasher gets called properly
        with mock.patch(f'blake2signer.hashers.blakehashers.hashlib.{choice}') as mock_hasher:
            mock_hasher.PERSON_SIZE = 8
            mock_hasher.MAX_KEY_SIZE = 12
            mock_hasher.MAX_DIGEST_SIZE = 16
            mock_hasher.return_value.digest.return_value = b'abc123'

            self.get_hasher(choice)

        calls = [mock.call(self.person, digest_size=8), mock.call().digest()]
        for secret in self.secrets:
            calls.append(mock.call(secret, digest_size=12, person=b'abc123'))
            calls.append(mock.call().digest())
        mock_hasher.assert_has_calls(calls)

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

        digest = hasher.digest(b'datadata', key=hasher.signing_key, salt=salt)

        assert expected_digest == digest

    @pytest.mark.parametrize(
        'choice',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
        ),
    )
    def test_signing_key_is_the_newest_one(self, choice: HasherChoice) -> None:
        """Test that the signing key is the newest one."""
        hasher = self.get_hasher(choice)

        assert hasher.keys[-1] == hasher.signing_key


class TestsBLAKE2HasherPy38(TestsBLAKE2Hasher):
    """BLAKE2Hasher tests, hack for Pytest under Python <=3.8."""

    __new__ = object.__new__


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

        assert len(self.secrets) == len(hasher.keys)
        assert self.secrets != hasher.keys
        assert sorted(self.secrets) != sorted(hasher.keys)

        for key in hasher.keys:
            assert blake3().key_size == len(key)

        # Ensure keys are actually derived
        with mock.patch.object(self.hasher_class, '_derive_key') as mock_derive_key:
            hasher = self.get_hasher()
        calls = []
        for secret in self.secrets:
            calls.append(mock.call(secret, person=hasher._person))
        mock_derive_key.assert_has_calls(calls)

        # Ensure the hasher gets called properly
        with mock.patch('blake2signer.hashers.blakehashers.blake3') as mock_hasher:
            mock_hasher.return_value.key_size = 16

            self.get_hasher()

        calls = []  # person is not derived
        derive_key_context = 'blake2signer 2021-12-29 18:04:37 BLAKE3Hasher key derivation'
        for secret in self.secrets:
            calls.append(mock.call(secret, derive_key_context=derive_key_context))
            calls.append(mock.call().update(self.person))
            calls.append(mock.call().digest(length=16))
        mock_hasher.assert_has_calls(calls)

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

        digest = hasher.digest(b'datadata', key=hasher.signing_key, salt=salt)

        assert expected_digest == digest

    def test_signing_key_is_the_newest_one(self) -> None:
        """Test that the signing key is the newest one."""
        hasher = self.get_hasher()

        assert hasher.keys[-1] == hasher.signing_key


class TestsBLAKE3HasherPy38(TestsBLAKE3Hasher):
    """BLAKE3Hasher tests, hack for Pytest under Python <=3.8."""

    __new__ = object.__new__
