"""Timestamp signers tests."""

import typing
from abc import ABC
from datetime import timedelta
from time import time
from unittest import mock

import pytest

from .bases import BaseTests
from .bases import Signature
from .bases import Signer
from .test_signer import TestsBlake2Signer
from .. import errors
from ..signers import Blake2Signer
from ..signers import Blake2TimestampSigner


class TimestampSignerTestsBase(BaseTests, ABC):
    """Base to test a timestamp signer."""

    @mock.patch('blake2signer.bases.time')
    def test_sign_unsign_deterministic(self, mock_time: mock.MagicMock) -> None:
        """Test sign and unsign with a deterministic signature."""
        mock_time.return_value = time()

        super().test_sign_unsign_deterministic()

    @mock.patch('blake2signer.bases.time')
    def test_sign_unsign_parts_deterministic(self, mock_time: mock.MagicMock) -> None:
        """Test signing and unsigning in parts deterministically."""
        mock_time.return_value = time()

        super().test_sign_unsign_parts_deterministic()

    @mock.patch('blake2signer.bases.time')
    def test_sign_is_unique_non_deterministic(self, mock_time: mock.MagicMock) -> None:
        """Test that each signing is unique because of salt."""
        mock_time.return_value = time()

        super().test_sign_is_unique_non_deterministic()

    @mock.patch('blake2signer.bases.time')
    def test_sign_parts_is_unique_non_deterministic(
        self,
        mock_time: mock.MagicMock,
    ) -> None:
        """Test that each signing in parts is unique because of salt."""
        mock_time.return_value = time()

        super().test_sign_parts_is_unique_non_deterministic()

    @mock.patch('blake2signer.bases.time')
    def test_sign_unsign_timestamp_expired(self, mock_time: mock.MagicMock) -> None:
        """Test unsigning with timestamp is correct."""
        timestamp = int(time())
        mock_time.return_value = timestamp
        signer = self.signer(self.secret)

        signed = self.sign(signer, self.data)

        mock_time.return_value += 10
        with pytest.raises(
                errors.ExpiredSignatureError,
                match='signature has expired',
        ) as exc:
            self.unsign(signer, signed)
        assert exc.value.__cause__ is None
        assert exc.value.timestamp.timestamp() == timestamp

    @mock.patch('blake2signer.bases.time')
    def test_sign_unsign_timestamp_future(self, mock_time: mock.MagicMock) -> None:
        """Test signing in the future, then unsigning, causes an exception."""
        timestamp = int(time())
        mock_time.return_value = timestamp
        signer = self.signer()
        signed = self.sign(signer, self.data)

        # Back to the future
        mock_time.return_value -= 10
        with pytest.raises(
                errors.ExpiredSignatureError,
                match='< 0 seconds',
        ) as exc:
            self.unsign(signer, signed, max_age=5)
        assert timestamp == exc.value.timestamp.timestamp()

    def test_unsign_wrong_data_without_timestamp(self) -> None:
        """Test unsign wrong data."""
        signer = self.signer()

        trick_signed = self.trick_sign(signer, self.data)
        with pytest.raises(
                errors.SignatureError,
                match='separator not found in timestamped data',
        ) as exc:
            self.unsign(signer, trick_signed)
        assert exc.value.__cause__ is None

        trick_signed = self.trick_sign(
            signer,
            signer._separator + signer._force_bytes(self.data),
        )
        with pytest.raises(
                errors.SignatureError,
                match='timestamp information is missing',
        ) as exc:
            self.unsign(signer, trick_signed, max_age=1)
        assert exc.value.__cause__ is None

    def test_unsign_wrong_timestamped_data(self) -> None:
        """Test unsign wrong timestamped data."""
        signer = self.signer()

        trick_signed = self.trick_sign(
            signer,
            b'-' + signer._separator + signer._force_bytes(self.data),
        )
        with pytest.raises(errors.DecodeError, match='can not be decoded') as exc:
            self.unsign(signer, trick_signed)
        assert exc.value.__cause__ is not None

    @mock.patch('blake2signer.bases.time')
    def test_sign_timestamp_overflow(self, mock_time: mock.MagicMock) -> None:
        """Test signing with timestamp after 2106 which causes an integer overflow.

        With 4 unsigned bytes we can represent up to 2106-02-07 3:28:15.
        """
        mock_time.return_value = int.from_bytes(b'\xff' * 4, 'big', signed=False) + 1
        signer = self.signer()

        with pytest.raises(RuntimeError):
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

    @pytest.mark.parametrize(
        'max_age',
        (2, 2.5, timedelta(hours=2)),
    )
    @mock.patch('blake2signer.bases.time')
    def test_max_age_can_be_changed(
        self,
        mock_time: mock.MagicMock,
        max_age: typing.Union[int, float, timedelta],
    ) -> None:
        """Test that max age can be changed correctly."""
        timestamp = int(time())
        mock_time.return_value = timestamp
        signer = self.signer()

        signed = self.sign(signer, self.data)
        assert self.data == self.unsign(signer, signed, max_age=max_age)

        if isinstance(max_age, timedelta):
            mock_time.return_value += max_age.total_seconds()
        else:
            mock_time.return_value += max_age
        mock_time.return_value += 0.1  # It has to be a bit bigger than max_age

        with pytest.raises(
                errors.ExpiredSignatureError,
                match='signature has expired',
        ) as exc:
            self.unsign(signer, signed, max_age=max_age)
        assert exc.value.__cause__ is None
        assert exc.value.timestamp.timestamp() == timestamp
