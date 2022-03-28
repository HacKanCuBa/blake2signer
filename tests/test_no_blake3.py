"""Test that everything works without `blake3` installed."""

from abc import ABC
from unittest import mock

import pkg_resources
import pytest

with mock.patch.object(
        pkg_resources,
        'get_distribution',
        side_effect=pkg_resources.DistributionNotFound,
):
    from blake2signer import errors
    from blake2signer.tests.bases import BaseTests
    from blake2signer.tests.test_serializersigner import TestsBlake2SerializerSigner
    from blake2signer.tests.test_serializersigner import TestsBlake2SerializerSignerTimestamp  # noqa: E501  # pylint: disable=C0301
    from blake2signer.tests.test_signer import TestsBlake2Signer
    from blake2signer.tests.test_timestampsigner import TestsBlake2TimestampSigner
    from blake2signer.hashers import blake3


class WithoutBLAKE3TestsBase(BaseTests, ABC):
    """Base tests without blake3."""

    def test_everything_works_without_blake3(self) -> None:
        """Test that this package works if `blake3` is not installed."""
        signer = self.signer()

        assert self.data == self.unsign(signer, self.sign(signer, self.data))

    def test_choosing_blake3_fails(self) -> None:
        """Test that choosing BLAKE3 without having it installed fails."""
        with pytest.raises(
                errors.MissingDependencyError,
                match='blake3 can not be selected',
        ):
            self.signer(hasher=self.signer_class.Hashers.blake3)


class TestsBlake2SignerWithoutBLAKE3(WithoutBLAKE3TestsBase, TestsBlake2Signer):
    """Blake2Signer without BLAKE3 tests."""


class TestsBlake2TimestampSignerWithoutBLAKE3(
        WithoutBLAKE3TestsBase,
        TestsBlake2TimestampSigner,
):
    """Blake2TimestampSigner without BLAKE3 tests."""


class TestsBlake2SerializerSignerWithoutBLAKE3(
        WithoutBLAKE3TestsBase,
        TestsBlake2SerializerSigner,
):
    """Blake2SerializerSigner without BLAKE3 tests."""


class TestsBlake2SerializerSignerTimestampWithoutBLAKE3(
        WithoutBLAKE3TestsBase,
        TestsBlake2SerializerSignerTimestamp,
):
    """Blake2SerializerSigner (with timestamp) without BLAKE3 tests."""


def test_executing_blake3_without_the_package_installed_fails() -> None:
    """Test that executing the blake3 function w/o the package installed fails."""
    with pytest.raises(
            errors.MissingDependencyError,
            match='blake3 can not be selected if it is not installed',
    ):
        blake3()
