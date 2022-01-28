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

    @pytest.mark.xfail(
        not has_blake3(),
        reason='blake3 is not installed',
        raises=errors.MissingDependencyError,
    )
    @pytest.mark.parametrize(
        ('version', 'hasher', 'signed', 'compat'),
        (
            (
                '1.2.1',
                HasherChoice.blake2b,
                '2exTNSllIBMpAkkd0SBv3r2_wew7q9t6SB_OVg.is compat ensured?',
                False,
            ),
            (
                '1.2.1',
                HasherChoice.blake2s,
                'nXsYsvLVNvqLatytrg_SevNvY_SLIw.is compat ensured?',
                False,
            ),
            (
                '2.0.0',
                HasherChoice.blake2b,
                '8lRrzthYNOHdxhkakSo34_jwOa_Mp_FQcFK8Sg.is compat ensured?',
                True,
            ),
            (
                '2.0.0',
                HasherChoice.blake2s,
                'L_jCeKUmWWAuXNATdnrvXmssf-IpGw.is compat ensured?',
                True,
            ),
            (
                '2.1.0',
                HasherChoice.blake2b,
                'Qu5_rlDNXDOO0ie9ZWbrkDgyxUrlQTmP-KJBLg.is compat ensured?',
                True,
            ),
            (
                '2.1.0',
                HasherChoice.blake2s,
                'TOsyPse3l0EWvhWPsQ6HAE30JlIYNA.is compat ensured?',
                True,
            ),
            (
                '2.2.0',
                HasherChoice.blake2b,
                '_RKzXIJZfg1cOV-mbNw9WX4wYBA2pcqdKrguoA.is compat ensured?',
                True,
            ),
            (
                '2.2.0',
                HasherChoice.blake2s,
                '8rsWR8Aoi8EeQI7CcS80zZ320Pr5Nw.is compat ensured?',
                True,
            ),
            (
                '2.2.0',
                HasherChoice.blake3,
                '9DbuBl_FqzvsspaCC6H23C8CEmRWH8mucCOXbA.is compat ensured?',
                True,
            ),
            (
                '2.3.0',
                HasherChoice.blake2b,
                'kHA3CsED0bqLXYZ0vGzuPbIU70lKeaUa-4PgAQ.is compat ensured?',
                True,
            ),
            (
                '2.3.0',
                HasherChoice.blake2s,
                'i_udo1_KBC9ff-iWqOoOHiq60YqojA.is compat ensured?',
                True,
            ),
            (
                '2.3.0',
                HasherChoice.blake3,
                '9OPOu3qaF616QQ81ut2bDtOf9O2Pqad_1lNZSw.is compat ensured?',
                True,
            ),
            (
                '2.4.0',
                HasherChoice.blake2b,
                'ZCLGwc0v0rzptgunF70vP1GrkNZDl4q7iGudCw.is compat ensured?',
                True,
            ),
            (
                '2.4.0',
                HasherChoice.blake2s,
                'PRdPO7n-rGAwLDVJ40jmbztPJYo6Ag.is compat ensured?',
                True,
            ),
            (
                '2.4.0',
                HasherChoice.blake3,
                'YoCHtjlT-s5m9yuJBn2DJix5vT5xMnuUVR5BBg.is compat ensured?',
                True,
            ),
        ),
    )
    def test_versions_compat(
        self,
        version: str,
        hasher: HasherChoice,
        signed: str,
        compat: bool,
    ) -> None:
        """Test if previous versions' signed data is compatible with the current one."""
        super().test_versions_compat(version, hasher, signed, compat)
