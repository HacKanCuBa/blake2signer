"""Timestamp signers tests."""
# pylint: disable=R0801

import typing
from abc import ABC
from datetime import timedelta
from math import isclose
from unittest import mock

import pytest

from .bases import BaseTests
from .bases import Signature
from .bases import Signer
from .test_signer import TestsBlake2Signer
from .. import errors
from ..hashers import HasherChoice
from ..hashers import has_blake3
from ..signers import Blake2Signer
from ..signers import Blake2TimestampSigner


class TimestampSignerTestsBase(BaseTests, ABC):
    """Base to test a timestamp signer."""

    now = 531810000.0  # Signatures for version compat test were made with this time
    patch_time = mock.patch('blake2signer.bases.get_current_time', return_value=now)
    mock_time: mock.MagicMock

    def setup_method(self):
        """Tests set-up."""
        self.mock_time = self.patch_time.start()

    def teardown_method(self):
        """Tests teardown."""
        self.patch_time.stop()

    @staticmethod
    def get_expired_signature_error_data(
        exc: errors.ExpiredSignatureError,
        *,
        signer: Signer,  # pylint: disable=W0613
    ) -> typing.Any:
        """Get expired signature error data."""
        return exc.data

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
    def test_sign_unsign_timestamp_expired(
        self,
        hasher: HasherChoice,
    ) -> None:
        """Test unsigning with timestamp is correct."""
        signer = self.signer(self.secret, hasher=hasher)
        signed = self.sign(signer, self.data)

        self.mock_time.return_value += 10
        with pytest.raises(
                errors.ExpiredSignatureError,
                match='signature has expired',
        ) as exc:
            self.unsign(signer, signed)

        assert exc.value.__cause__ is None
        assert isclose(self.now, exc.value.timestamp.timestamp())
        assert self.data == self.get_expired_signature_error_data(exc.value, signer=signer)

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
    def test_sign_unsign_timestamp_future(
        self,
        hasher: HasherChoice,
    ) -> None:
        """Test signing in the future, then unsigning, causes an exception."""
        signer = self.signer(hasher=hasher)
        signed = self.sign(signer, self.data)

        # Back to the future
        self.mock_time.return_value -= 10
        with pytest.raises(
                errors.ExpiredSignatureError,
                match='< 0 seconds',
        ) as exc:
            self.unsign(signer, signed, max_age=5)

        assert isclose(self.now, exc.value.timestamp.timestamp())

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
    def test_sign_unsign_timestamp_in_exc_is_an_aware_datetime(
        self,
        hasher: HasherChoice,
    ) -> None:
        """Test that the timestamp in ExpiredSignatureError is an aware datetime."""
        signer = self.signer(hasher=hasher)
        signed = self.sign(signer, self.data)

        self.mock_time.return_value += 10
        with pytest.raises(
                errors.ExpiredSignatureError,
                match='signature has expired',
        ) as exc:
            self.unsign(signer, signed, max_age=5)

        assert exc.value.__cause__ is None
        assert isclose(self.now, exc.value.timestamp.timestamp())
        assert timedelta() == exc.value.timestamp.utcoffset()  # Aware in UTC

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
    def test_unsign_wrong_data_without_timestamp(self, hasher: HasherChoice) -> None:
        """Test unsign wrong data."""
        signer = self.signer(hasher=hasher)
        trick_signed = self.trick_sign(signer, self.data)

        with pytest.raises(
                errors.SignatureError,
                match='separator not found in timestamped data',
        ) as exc:
            self.unsign(signer, trick_signed)

        assert exc.value.__cause__ is None

        trick_signed = self.trick_sign(
            signer,
            signer._separator + signer._force_bytes(self.data),  # pylint: disable=W0212
        )

        with pytest.raises(
                errors.SignatureError,
                match='timestamp information is missing',
        ) as exc:
            self.unsign(signer, trick_signed, max_age=1)

        assert exc.value.__cause__ is None

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
    def test_unsign_wrong_timestamped_data(self, hasher: HasherChoice) -> None:
        """Test unsign wrong timestamped data."""
        signer = self.signer(hasher=hasher)
        trick_signed = self.trick_sign(
            signer,
            b'-' + signer._separator + signer._force_bytes(self.data),  # pylint: disable=W0212
        )

        with pytest.raises(errors.DecodeError, match='can not be decoded') as exc:
            self.unsign(signer, trick_signed)

        assert exc.value.__cause__ is not None

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
    def test_sign_timestamp_overflow(
        self,
        hasher: HasherChoice,
    ) -> None:
        """Test signing with timestamp after 2106 which causes an integer overflow.

        With four unsigned bytes, we can represent up to 2106-02-07 3:28:15.
        """
        self.mock_time.return_value = int.from_bytes(b'\xff' * 4, 'big') + 1
        signer = self.signer(hasher=hasher)

        with pytest.raises(RuntimeError, match='can not represent this timestamp in bytes'):
            self.sign(signer, self.data)

    def test_sign_unsign_with_different_signer(self) -> None:
        """Test signing and unsigning with different signers fails correctly."""
        signer1 = self.signer()
        signer2 = Blake2Signer(self.secret)

        signed1 = self.sign(signer1, self.data)
        with pytest.raises(errors.InvalidSignatureError):
            signer2.unsign(signed1)

        signed2 = signer2.sign(self.data)
        with pytest.raises(errors.InvalidSignatureError):
            self.unsign(signer1, signed2)


class TestsBlake2TimestampSigner(TimestampSignerTestsBase, TestsBlake2Signer):
    """Blake2TimestampSigner tests."""

    @property
    def signer_class(self) -> typing.Type[Signer]:
        """Get the signer class to test."""
        return Blake2TimestampSigner

    def unsign(
        self,
        signer: Signer,
        signed_data: typing.Union[str, bytes],
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Unsign signed data with the signer."""
        kwargs.setdefault('max_age', 5)
        return signer.unsign(signed_data, **kwargs)

    def unsign_parts(
        self,
        signer: Signer,
        signature: Signature,
        **kwargs: typing.Any,
    ) -> typing.Any:
        """Unsign signature with the signer."""
        kwargs.setdefault('max_age', 5)
        return signer.unsign_parts(signature, **kwargs)

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
        'max_age',
        (2, 2.5, timedelta(hours=2)),
    )
    def test_max_age_can_be_changed(
        self,
        max_age: typing.Union[int, float, timedelta],
        hasher: HasherChoice,
    ) -> None:
        """Test that max age can be changed correctly."""
        signer = self.signer(hasher=hasher)
        signed = self.sign(signer, self.data)

        assert self.data == self.unsign(signer, signed, max_age=max_age)

        # called twice, during sign and unsign
        assert 2 == self.mock_time.call_count

        if isinstance(max_age, timedelta):
            self.mock_time.return_value += max_age.total_seconds()
        else:
            self.mock_time.return_value += max_age
        self.mock_time.return_value += 0.1  # It has to be a bit bigger than max_age

        with pytest.raises(
                errors.ExpiredSignatureError,
                match='signature has expired',
        ) as exc:
            self.unsign(signer, signed, max_age=max_age)

        assert exc.value.__cause__ is None
        assert isclose(self.now, exc.value.timestamp.timestamp())
        assert self.data == exc.value.data

        # called one more time during unsign
        assert 3 == self.mock_time.call_count

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
    def test_max_age_can_be_null(
        self,
        hasher: HasherChoice,
    ) -> None:
        """Test that `max_age` can be null."""
        signer = self.signer(hasher=hasher)

        signed = self.sign(signer, self.data)
        unsigned = self.unsign(signer, signed, max_age=None)

        assert self.data == unsigned

        # called once when getting the time during sign, and not during unsign
        self.mock_time.assert_called_once_with()

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
    def test_max_age_can_be_null_in_parts(
        self,
        hasher: HasherChoice,
    ) -> None:
        """Test that `max_age` can be null."""
        signer = self.signer(hasher=hasher)

        signed = self.sign_parts(signer, self.data)
        unsigned = self.unsign_parts(signer, signed, max_age=None)

        assert self.data == unsigned

        # called once when getting the time during sign, and not during unsign
        self.mock_time.assert_called_once_with()

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
                'tUWWADmGW7LvDiYIWAf9thfZTdJJdMB8ZPihqg.H7LG0A.is compat ensured?',
                False,
            ),
            (
                '1.2.1',
                HasherChoice.blake2s,
                'bEIaDntvjGRBlztHCioRz4iIHtiN-Q.H7LG0A.is compat ensured?',
                False,
            ),
            (
                '2.0.0',
                HasherChoice.blake2b,
                '8PRyw4n2iYujfxgMGJn4WiQ_MS2-0pd80qZx5g.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.0.0',
                HasherChoice.blake2s,
                'i4vdq7u7374NorxdBngDlEYpHsA_MQ.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.1.0',
                HasherChoice.blake2b,
                'fD4x0dnu-GJxY6da2Js4A_KY3w9vrQRNPFqOcA.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.1.0',
                HasherChoice.blake2s,
                'sVRBofd44aqGYBrC0-fLIGsas1xYgA.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.2.0',
                HasherChoice.blake2b,
                'oRWSC9lUQuR281W0U44-88asu9zUpiP3-_cIGQ.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.2.0',
                HasherChoice.blake2s,
                'N6Zv1WkCDJP9fdReelAUXMw8NAffCA.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.2.0',
                HasherChoice.blake3,
                '9bDZwVzVZOOONyA0ZdirK2Z3s_uh6fgV2j0Cww.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.3.0',
                HasherChoice.blake2b,
                'HX9OjTKOyov0uRb2RnhBPMl74UPXt3Eq_b-GNw.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.3.0',
                HasherChoice.blake2s,
                'WDwpKeBuILEplMlP58IcPGkUx12hjA.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.3.0',
                HasherChoice.blake3,
                'NFOIZnYZ545GRYEkQkBCIvua5ceBMOsVPHnxOA.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.4.0',
                HasherChoice.blake2b,
                'vdBOa1kSIFeCWZDsb0EepJpWYzvfuC2PSbINyw.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.4.0',
                HasherChoice.blake2s,
                'JegLzJFvA_MFzgdkWURVQD-P05fX6w.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.4.0',
                HasherChoice.blake3,
                'MPamwhHV0SP28U1jSpCsS7x_Rz3UvirqDjMsvg.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.5.0',
                HasherChoice.blake2b,
                'LxSytFKm4x7EopjajsFcAY1ofPr27VXISLzf_w.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.5.0',
                HasherChoice.blake2s,
                'v9J0bjY8z4kLzm594_C42ldMjm9B5w.H7LG0A.is compat ensured?',
                True,
            ),
            (
                '2.5.0',
                HasherChoice.blake3,
                'o5EebTjPPGFjYiXwlVsV88legFhUbDT-wGVcoQ.H7LG0A.is compat ensured?',
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
