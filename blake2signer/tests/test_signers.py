"""Signers module tests."""

from datetime import datetime
from datetime import timedelta
from unittest import TestCase
from unittest import mock

from ..errors import DecodeError
from ..errors import ExpiredSignatureError
from ..errors import InvalidOptionError
from ..errors import InvalidSignatureError
from ..signers import Blake2Signer
from ..signers import Blake2TimestampSigner
from ..signers import Hashers_


class Blake2SignerTests(TestCase):
    """Test Blake2Signer class."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.key = b'0123456789012345'
        self.data = b'datadata'

    def test_initialisation_defaults(self) -> None:
        """Test correct class defaults initialisation."""
        signer = Blake2Signer(self.key)
        self.assertIsInstance(signer, Blake2Signer)

        signer = Blake2Signer(self.key, hasher=Hashers_.blake2s)
        self.assertIsInstance(signer, Blake2Signer)

    def test_initialisation_all_options(self) -> None:
        """Test correct class initialisation with all options."""
        signer = Blake2Signer(
            self.key,
            person=b'acab',
            hasher=Blake2Signer.Hashers.blake2s,
            digest_size=10,
        )
        self.assertIsInstance(signer, Blake2Signer)

    def test_sign(self) -> None:
        """Test signing is correct."""
        signer = Blake2Signer(self.key)
        signed = signer.sign(self.data)
        self.assertIsInstance(signed, bytes)
        expected_size = len(self.data) + signer.salt_size + signer.signature_size
        self.assertEqual(len(signed), expected_size)

    def test_unsign(self) -> None:
        """Test unsigning is correct."""
        signer = Blake2Signer(self.key)
        signed = signer.sign(self.data)
        unsigned = signer.unsign(signed)
        self.assertEqual(unsigned, self.data)

    def test_nonbytes(self) -> None:
        """Test non-bytes values for parameters such as key, person, data, etc."""
        key = self.key.decode()
        signer = Blake2Signer(key)  # type: ignore
        self.assertIsInstance(signer, Blake2Signer)

        string = self.data.decode()
        signed = signer.sign(string)  # type: ignore
        self.assertIsInstance(signed, bytes)

        unsigned = signer.unsign(signed)
        self.assertIsInstance(unsigned, bytes)
        self.assertEqual(unsigned, self.data)


class Blake2SignerErrorTests(TestCase):
    """Test Blake2Signer class for errors."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.key = b'0123456789012345'
        self.data = b'datadata'

    def test_key_too_short(self) -> None:
        """Test key too short."""
        with self.assertRaises(InvalidOptionError):
            Blake2Signer(b'12345678')

    def test_key_too_long(self) -> None:
        """Test key too long."""
        with self.assertRaises(InvalidOptionError):
            Blake2Signer(b'0' * 65)

        with self.assertRaises(InvalidOptionError):
            Blake2Signer(b'0' * 33, hasher=Hashers_.blake2s)

    def test_digest_too_small(self) -> None:
        """Test digest too small."""
        with self.assertRaises(InvalidOptionError):
            Blake2Signer(self.key, digest_size=4)

        with self.assertRaises(InvalidOptionError):
            Blake2Signer(self.key, digest_size=4, hasher=Hashers_.blake2s)

    def test_digest_too_large(self) -> None:
        """Test digest too large."""
        with self.assertRaises(InvalidOptionError):
            Blake2Signer(self.key, digest_size=65)

        with self.assertRaises(InvalidOptionError):
            Blake2Signer(self.key, digest_size=33, hasher=Hashers_.blake2s)

    def test_wrong_options(self) -> None:
        """Test parameters out of bounds."""
        with self.assertRaises(InvalidOptionError):
            Blake2Signer(self.key, person=b'0' * 17)

    def test_unsign_wrong_data(self) -> None:
        """Test unsign with wrong data."""
        signer = Blake2Signer(self.key)
        with self.assertRaises(DecodeError, msg='signed data is too short'):
            signer.unsign(b'12345678')

    def test_unsign_invalid_signature(self) -> None:
        """Test unsign with invalid signature."""
        signer = Blake2Signer(self.key)
        with self.assertRaises(InvalidSignatureError):
            signer.unsign(b'0' * (signer.salt_size + signer.signature_size))


class Blake2TimestampSignerTests(TestCase):
    """Test Blake2TimestampSigner class."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.key = b'0123456789012345'
        self.data = b'datadata'

    def test_initialisation_defaults(self) -> None:
        """Test correct class defaults initialisation."""
        signer = Blake2TimestampSigner(self.key)
        self.assertIsInstance(signer, Blake2TimestampSigner)

        signer = Blake2TimestampSigner(self.key, hasher=Hashers_.blake2s)
        self.assertIsInstance(signer, Blake2TimestampSigner)

    def test_sign(self) -> None:
        """Test signing is correct."""
        signer = Blake2TimestampSigner(self.key)
        signed = signer.sign(self.data)
        self.assertIsInstance(signed, bytes)
        added_size = signer.timestamp_size + signer.salt_size + signer.signature_size
        self.assertEqual(
            len(signed),
            len(self.data) + added_size,
        )

    def test_unsign(self) -> None:
        """Test unsigning is correct."""
        signer = Blake2TimestampSigner(self.key)
        signed = signer.sign(self.data)
        unsigned = signer.unsign(signed, max_age=timedelta(seconds=1))
        self.assertEqual(unsigned, self.data)


class Blake2TimestampSignerErrorTests(TestCase):
    """Test Blake2TimestampSigner class for errors."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.key = b'0123456789012345'
        self.data = b'datadata'

    def test_unsign_timestamp_expired(self) -> None:
        """Test unsigning with timestamp is correct."""
        from time import sleep

        timeout = 0.00001
        signer = Blake2TimestampSigner(self.key)
        signed = signer.sign(self.data)
        sleep(timeout)
        with self.assertRaises(ExpiredSignatureError):
            signer.unsign(signed, max_age=timeout)

    def test_unsign_wrong_data(self) -> None:
        """Test unsign wrong data."""
        # To test this I need a valid signature w/ wrong timestamp
        signed = Blake2Signer(self.key).sign(b'0')
        with self.assertRaises(DecodeError):
            Blake2TimestampSigner(self.key).unsign(signed, max_age=1)

    @mock.patch('blake2signer.signers.time')
    def test_sign_timestamp_overflow(self, mock_time: mock.MagicMock) -> None:
        """Test signing with timestamp after 2106 which causes an integer overflow.

        With 4 unsigned bytes we can represent up to 2106-02-07 3:28:15.
        """
        # The max date w/ 4 bytes is obtained as datetime.fromtimestamp()
        # with the input being int.from_bytes(b'\xff' * 4, 'big', signed=False)
        mock_time.return_value = datetime(year=2106, month=2, day=8).timestamp()
        with self.assertRaises(NotImplementedError):
            Blake2TimestampSigner(self.key).sign(self.data)
