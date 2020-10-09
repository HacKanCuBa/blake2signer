"""Signers module tests."""

from datetime import datetime
from datetime import timedelta
from unittest import TestCase
from unittest import mock

from .. import errors
from ..signers import Blake2Signer
from ..signers import Blake2TimestampSigner
from ..signers import Hashers_


class Blake2SignerTests(TestCase):
    """Test Blake2Signer class."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.secret = b'0123456789012345'
        self.data = b'datadata'
        self.signed = (
            b'r2wBlTL7ogt4SfyxBeJ3gqdAs9CR8UfIWakJcyqMPdQBcb-S0LTDRoTDR7i-DypyN'
            b'KWUVU96eUb8o-PlsT50DGOfeWLJcurMUtJcPg.datadata'
        )
        self.person = b'acab'

    def test_initialisation_defaults(self) -> None:
        """Test correct class defaults initialisation."""
        signer = Blake2Signer(self.secret)
        self.assertIsInstance(signer, Blake2Signer)

        signer = Blake2Signer(self.secret, hasher=Hashers_.blake2s)
        self.assertIsInstance(signer, Blake2Signer)

    def test_sign_unsign_all_options(self) -> None:
        """Test correct signing and unsigning using all options."""
        signer = Blake2Signer(
            self.secret,
            personalisation=self.person,
            hasher=Blake2Signer.Hashers.blake2s,
            digest_size=32,
        )
        self.assertIsInstance(signer, Blake2Signer)

        signed = signer.sign(self.data)
        unsigned = signer.unsign(signed)
        self.assertEqual(unsigned, self.data)

    def test_sign(self) -> None:
        """Test signing is correct."""
        signer = Blake2Signer(self.secret)
        signed = signer.sign(self.data)
        self.assertIsInstance(signed, bytes)
        self.assertEqual(len(signed), 111)

    def test_unsign(self) -> None:
        """Test unsigning is correct."""
        signer = Blake2Signer(self.secret)
        unsigned = signer.unsign(self.signed)
        self.assertEqual(unsigned, self.data)

    def test_sign_unsign_with_person(self) -> None:
        """Test signing and unsigning using person is correct."""
        signer = Blake2Signer(self.secret, personalisation=self.person)
        signed = signer.sign(self.data)
        unsigned = signer.unsign(signed)
        self.assertEqual(unsigned, self.data)

    def test_nonbytes_inputs(self) -> None:
        """Test non-bytes values for parameters such as secret, person, data, etc."""
        secret = self.secret.decode()
        # noinspection PyTypeChecker
        signer = Blake2Signer(
            secret,  # type: ignore
            personalisation=self.person.decode(),  # type: ignore
        )
        self.assertIsInstance(signer, Blake2Signer)

        string = self.data.decode()
        signed = signer.sign(string)
        self.assertIsInstance(signed, bytes)

        unsigned = signer.unsign(signed.decode())
        self.assertIsInstance(unsigned, bytes)
        self.assertEqual(unsigned, self.data)

    def test_sign_is_unique(self) -> None:
        """Test that each signing is unique because of salt."""
        signer = Blake2Signer(self.secret)

        signed1 = signer.sign(self.data)
        signed2 = signer.sign(self.data)

        self.assertEqual(len(signed1), len(signed2))
        self.assertNotEqual(signed1, signed2)


class Blake2SignerErrorTests(TestCase):
    """Test Blake2Signer class for errors."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.secret = b'0123456789012345'
        self.data = b'datadata'
        self.person = b'acab'

    def test_secret_too_short(self) -> None:
        """Test secret too short."""
        with self.assertRaises(errors.InvalidOptionError):
            Blake2Signer(b'12345678')

    def test_digest_too_small(self) -> None:
        """Test digest too small."""
        with self.assertRaises(errors.InvalidOptionError):
            Blake2Signer(self.secret, digest_size=4)

        with self.assertRaises(errors.InvalidOptionError):
            Blake2Signer(self.secret, digest_size=4, hasher=Hashers_.blake2s)

    def test_digest_too_large(self) -> None:
        """Test digest too large."""
        with self.assertRaises(errors.InvalidOptionError):
            Blake2Signer(self.secret, digest_size=65)

        with self.assertRaises(errors.InvalidOptionError):
            Blake2Signer(self.secret, digest_size=33, hasher=Hashers_.blake2s)

    def test_unsign_wrong_data(self) -> None:
        """Test unsign with wrong data."""
        signer = Blake2Signer(self.secret)

        with self.assertRaises(errors.SignatureError) as cm:  # using `msg` doesn't work
            signer.unsign(b'12345678')
        self.assertEqual(str(cm.exception), 'separator not found in signed data')

        with self.assertRaises(errors.SignatureError) as cm:
            signer.unsign(b'123.45678')
        self.assertEqual(str(cm.exception), 'signature is too short')

    def test_unsign_invalid_signature(self) -> None:
        """Test unsign with invalid signature."""
        signer = Blake2Signer(self.secret)
        with self.assertRaises(errors.InvalidSignatureError):
            signer.unsign(b'0' * (signer._salt_size + signer.MIN_DIGEST_SIZE) + b'.')

    def test_sign_unsign_wrong_person_same_key(self) -> None:
        """Test signing and unsigning using wrong person fails despite same secret."""
        signed = Blake2Signer(self.secret, personalisation=self.person).sign(self.data)
        signer = Blake2Signer(self.secret)

        with self.assertRaises(errors.InvalidSignatureError):
            signer.unsign(signed)

    def test_wrong_nonbytes_inputs(self) -> None:
        """Test wrong non-bytes values for parameters such as secret, person, etc."""
        with self.assertRaises(errors.ConversionError):
            # noinspection PyTypeChecker
            Blake2Signer(secret=1.0)  # type: ignore

        with self.assertRaises(errors.ConversionError):
            # noinspection PyTypeChecker
            Blake2Signer(self.secret, personalisation=1.0)  # type: ignore

        with self.assertRaises(errors.ConversionError):
            # noinspection PyTypeChecker
            Blake2Signer(self.secret).sign(1.0)  # type: ignore

        with self.assertRaises(errors.ConversionError):
            # noinspection PyTypeChecker
            Blake2Signer(self.secret).unsign(1.0)  # type: ignore


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
        self.secret = b'0123456789012345'
        self.data = b'datadata'
        self.signed = (
            b'bbc3JgXUWr3oDNh4Z50OVUjxZ_Mtkdz-zi30vq4gHjN5R97NLuLd4gacIxer4fpPl'
            b'cBgo_hjhHbs0AgATFlcoUP5sKpuPiHqcqFFSw.X35cyA.datadata'
        )

    def test_unsign_timestamp_expired(self) -> None:
        """Test unsigning with timestamp is correct."""
        signer = Blake2TimestampSigner(self.secret)
        with self.assertRaises(errors.ExpiredSignatureError):
            signer.unsign(self.signed, max_age=1)

    def test_unsign_wrong_data(self) -> None:
        """Test unsign wrong data."""
        signer = Blake2TimestampSigner(self.secret)
        trick_signer = Blake2Signer(self.secret)
        trick_signer._key = signer._key
        trick_signer._person = signer._person

        trick_signed = trick_signer.sign(self.data)
        with self.assertRaises(errors.SignatureError) as cm:
            signer.unsign(trick_signed, max_age=1)
        self.assertEqual(str(cm.exception), 'separator not found in timestamped data')

        trick_signed = trick_signer.sign(b'.' + self.data)
        with self.assertRaises(errors.SignatureError) as cm:
            signer.unsign(trick_signed, max_age=1)
        self.assertEqual(str(cm.exception), 'timestamp information is missing')

        trick_signed = trick_signer.sign(b'-.' + self.data)
        with self.assertRaises(errors.SignatureError) as cm:
            signer.unsign(trick_signed, max_age=1)
        self.assertEqual(str(cm.exception), 'timestamp can not be decoded')

    @mock.patch('blake2signer.signers.time')
    def test_sign_timestamp_overflow(self, mock_time: mock.MagicMock) -> None:
        """Test signing with timestamp after 2106 which causes an integer overflow.

        With 4 unsigned bytes we can represent up to 2106-02-07 3:28:15.
        """
        # The max date w/ 4 bytes is obtained as datetime.fromtimestamp()
        # with the input being int.from_bytes(b'\xff' * 4, 'big', signed=False)
        mock_time.return_value = datetime(year=2106, month=2, day=8).timestamp()
        signer = Blake2TimestampSigner(self.secret)

        with self.assertRaises(RuntimeError):
            signer.sign(self.data)
