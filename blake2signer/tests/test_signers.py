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
        self.signed = (
            b'pJn2ZVHShFshyqaP96VtfoDV3T80VhPMb3z1XoY7165SegBY3UZSs0djHbSuNRhhZP'
            b'ixDgVPd32_AEOMgU9Dkn4epDiKEqrcPP_IDg.datadata'
        )
        self.person = b'acab'

    def test_initialisation_defaults(self) -> None:
        """Test correct class defaults initialisation."""
        signer = Blake2Signer(self.key)
        self.assertIsInstance(signer, Blake2Signer)

        signer = Blake2Signer(self.key, hasher=Hashers_.blake2s)
        self.assertIsInstance(signer, Blake2Signer)

    def test_sign_unsign_all_options(self) -> None:
        """Test correct signing and unsigning using all options."""
        signer = Blake2Signer(
            self.key,
            person=self.person,
            hasher=Blake2Signer.Hashers.blake2s,
            digest_size=10,
        )
        self.assertIsInstance(signer, Blake2Signer)

        signed = signer.sign(self.data)
        unsigned = signer.unsign(signed)
        self.assertEqual(unsigned, self.data)

    def test_sign(self) -> None:
        """Test signing is correct."""
        signer = Blake2Signer(self.key)
        signed = signer.sign(self.data)
        self.assertIsInstance(signed, bytes)
        self.assertEqual(len(signed), 111)

    def test_unsign(self) -> None:
        """Test unsigning is correct."""
        signer = Blake2Signer(self.key)
        unsigned = signer.unsign(self.signed)
        self.assertEqual(unsigned, self.data)

    def test_sign_unsign_with_person(self) -> None:
        """Test signing and unsigning using person is correct."""
        signer = Blake2Signer(self.key, person=self.person)
        signed = signer.sign(self.data)
        unsigned = signer.unsign(signed)
        self.assertEqual(unsigned, self.data)


class Blake2SignerErrorTests(TestCase):
    """Test Blake2Signer class for errors."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.key = b'0123456789012345'
        self.data = b'datadata'
        self.person = b'acab'

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

        with self.assertRaises(DecodeError) as cm:  # using `msg` doesn't seem to work
            signer.unsign(b'12345678')
        self.assertEqual(str(cm.exception), 'separator not found in signed data')

        with self.assertRaises(DecodeError) as cm:
            signer.unsign(b'123.45678')
        self.assertEqual(str(cm.exception), 'signature is too short')

    def test_unsign_invalid_signature(self) -> None:
        """Test unsign with invalid signature."""
        signer = Blake2Signer(self.key)
        with self.assertRaises(InvalidSignatureError):
            signer.unsign(b'0' * (signer.salt_size + signer.MIN_DIGEST_SIZE) + b'.')

    def test_sign_unsign_wrong_person_same_key(self) -> None:
        """Test signing and unsigning using wrong person fails despite same key."""
        signed = Blake2Signer(self.key, person=self.person).sign(self.data)
        signer = Blake2Signer(self.key)

        with self.assertRaises(InvalidSignatureError):
            signer.unsign(signed)


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
        self.assertEqual(len(signed), 118)

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
        self.signed = (
            b'qxF4PE-7fkpLBW3kJXWQFzRD0eDIOAvjU0eQwWbhegEV4tN-e8a4VQs2eSx_gQJRfX'
            b'TtTJcqBVMRJ02W0OJGqFWnx82SvsWjoMucOg.X31T8w.datadata'
        )

    def test_unsign_timestamp_expired(self) -> None:
        """Test unsigning with timestamp is correct."""
        signer = Blake2TimestampSigner(self.key)
        with self.assertRaises(ExpiredSignatureError):
            signer.unsign(self.signed, max_age=1)

    def test_unsign_wrong_data(self) -> None:
        """Test unsign wrong data."""
        signer = Blake2TimestampSigner(self.key)

        with self.assertRaises(DecodeError) as cm:
            signer.unsign(
                b'pJn2ZVHShFshyqaP96VtfoDV3T80VhPMb3z1XoY7165SegBY3UZSs0djHbSuNRhhZP'
                b'ixDgVPd32_AEOMgU9Dkn4epDiKEqrcPP_IDg.datadata',
                max_age=1,
            )
        self.assertEqual(str(cm.exception), 'separator not found in timestamped data')

        with self.assertRaises(DecodeError) as cm:
            signer.unsign(
                b'ZMtxZo7crIb3R-S-dijfaITH484PdbsnJ0RgDUd7DWzu8JyR-3USae3yBR1_dX'
                b'REyiOHBuMFqFTQlbP3Jo0Ihkfma6ZOwsmnt-03GA..datadata',
                max_age=1,
            )
        self.assertEqual(str(cm.exception), 'timestamp information is missing')

        with self.assertRaises(DecodeError) as cm:
            signer.unsign(
                b'9FsZKp46TyH98l0YWuBqJtnAaXUP0x-CO37h9SGWVKi3ywg85zkkvUrKipGjRV'
                b'BSARC2BG32aq5P7zH_uTSM0By5SykYq5ileXgm4g.-.datadata',
                max_age=1,
            )
        self.assertEqual(str(cm.exception), 'encoded timestamp is not valid')

    @mock.patch('blake2signer.signers.time')
    def test_sign_timestamp_overflow(self, mock_time: mock.MagicMock) -> None:
        """Test signing with timestamp after 2106 which causes an integer overflow.

        With 4 unsigned bytes we can represent up to 2106-02-07 3:28:15.
        """
        # The max date w/ 4 bytes is obtained as datetime.fromtimestamp()
        # with the input being int.from_bytes(b'\xff' * 4, 'big', signed=False)
        mock_time.return_value = datetime(year=2106, month=2, day=8).timestamp()
        signer = Blake2TimestampSigner(self.key)

        with self.assertRaises(RuntimeError):
            signer.sign(self.data)
