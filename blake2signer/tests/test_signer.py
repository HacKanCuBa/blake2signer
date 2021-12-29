"""Signers tests."""

import typing

import pytest

from .bases import BaseTests
from .bases import Signature
from .bases import Signer
from .. import errors
from ..hashers import HasherChoice
from ..hashers import has_blake3
from ..signers import Blake2Signer


class TestsBlake2Signer(BaseTests):
    """Blake2Signer tests."""

    @property
    def signer_class(self) -> typing.Type[Signer]:
        """Get the signer class to test."""
        return Blake2Signer

    @property
    def signature_type(self) -> typing.Type[typing.Union[str, bytes]]:
        """Get the signature type for the signer (`bytes`)."""
        return bytes

    def sign(
        self,
        signer: Signer,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> typing.AnyStr:
        """Sign data with the signer."""
        return signer.sign(data)

    def unsign(
        self,
        signer: Signer,
        signed_data: typing.Union[str, bytes],
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Unsign signed data with the signer."""
        return signer.unsign(signed_data)

    def sign_parts(
        self,
        signer: Signer,
        data: typing.Any,
        **kwargs: typing.Any,
    ) -> Signature:
        """Sign data with the signer in parts."""
        return signer.sign_parts(data)

    def unsign_parts(
        self,
        signer: Signer,
        signature: Signature,
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Unsign signature with the signer."""
        return signer.unsign_parts(signature)

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        'hasher',
        (
            HasherChoice.blake2b,
            HasherChoice.blake2s,
            HasherChoice.blake3,
        ),
    )
    @pytest.mark.parametrize(
        'data',
        ('datadata', b'datadata'),
    )
    def test_data_can_be_string_or_bytes(
        self,
        data: typing.AnyStr,
        hasher: HasherChoice,
    ) -> None:
        """Test that data can be either bytes or string."""
        signer = self.signer(hasher=hasher)

        unsigned = self.unsign(signer, self.sign(signer, data))
        if isinstance(data, bytes):
            assert data == unsigned
        else:
            assert data.encode() == unsigned
