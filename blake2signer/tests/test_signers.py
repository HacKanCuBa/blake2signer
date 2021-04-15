"""Signers module tests."""

import hashlib
import json
import typing
import zlib
from datetime import datetime
from datetime import timedelta
from secrets import token_bytes
from unittest import TestCase
from unittest import mock

from .. import errors
from ..encoders import B32Encoder
from ..encoders import B64URLEncoder
from ..interfaces import EncoderInterface
from ..serializers import JSONSerializer
from ..signers import Blake2SerializerSigner
from ..signers import Blake2Signer
from ..signers import Blake2TimestampSigner
from ..utils import b64encode


# noinspection PyArgumentEqualDefault
class Blake2SignerTests(TestCase):
    """Test Blake2Signer class."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.secret = b'0123456789012345'
        self.data = b'datadata'
        self.signed = (
            b'nqQeVQRD_h3uvZLQZ_dLxhpv-Ua9ckfSMuzc3VJGlMvGtKgYuJl3E9mbY2zZRQut'
            b'hvEtItZNMnA7kBz9grVDnIpxn1UNXeQVdXcwsg.datadata'
        )
        self.person = b'acab'
        self.digest_size = 64

    def test_initialisation_defaults(self) -> None:
        """Test correct class defaults initialisation."""
        signer = Blake2Signer(self.secret)
        self.assertIsInstance(signer, Blake2Signer)
        self.assertIs(signer._hasher, hashlib.blake2b)

        signer = Blake2Signer(self.secret, hasher=Blake2Signer.Hashers.blake2s)
        self.assertIsInstance(signer, Blake2Signer)
        self.assertIs(signer._hasher, hashlib.blake2s)

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
        self.assertEqual(len(signed), 47)

    def test_unsign(self) -> None:
        """Test unsigning is correct."""
        signer = Blake2Signer(self.secret, digest_size=self.digest_size)
        unsigned = signer.unsign(self.signed)
        self.assertEqual(unsigned, self.data)

    def test_sign_unsign_with_person(self) -> None:
        """Test signing and unsigning using person is correct."""
        signer = Blake2Signer(self.secret, personalisation=self.person)
        signed = signer.sign(self.data)
        unsigned = signer.unsign(signed)
        self.assertEqual(unsigned, self.data)

    def test_string_instead_of_bytes_inputs(self) -> None:
        """Test non-bytes values for parameters such as secret, person, data, etc."""
        secret = self.secret.decode()
        signer = Blake2Signer(
            secret,
            personalisation=self.person.decode(),
            separator=',',
        )
        self.assertIsInstance(signer, Blake2Signer)

        string = self.data.decode()
        signed = signer.sign(string)
        self.assertIsInstance(signed, bytes)

        unsigned = signer.unsign(signed.decode())
        self.assertIsInstance(unsigned, bytes)
        self.assertEqual(unsigned, self.data)

    def test_sign_is_unique_non_deterministic(self) -> None:
        """Test that each signing is unique because of salt."""
        signer = Blake2Signer(self.secret, deterministic=False)

        signed1 = signer.sign(self.data)
        signed2 = signer.sign(self.data)

        self.assertEqual(len(signed1), len(signed2))
        self.assertNotEqual(signed1, signed2)

        unsigned1 = signer.unsign(signed1)
        self.assertEqual(self.data, unsigned1)

        unsigned2 = signer.unsign(signed2)
        self.assertEqual(self.data, unsigned2)

    def test_initialisation_hasher_as_string(self) -> None:
        """Test initialisation with hasher as string."""
        signer = Blake2Signer(self.secret, hasher='blake2b')
        self.assertIs(signer._hasher, hashlib.blake2b)

        signer = Blake2Signer(self.secret, hasher='blake2s')
        self.assertIs(signer._hasher, hashlib.blake2s)

    def test_sign_unsign_deterministic(self) -> None:
        """Test sign and unsign with a deterministic signature."""
        signer = Blake2Signer(self.secret, deterministic=True)

        signed = signer.sign(self.data)
        signed2 = signer.sign(self.data)
        self.assertEqual(signed, signed2)

        unsigned = signer.unsign(signed)
        self.assertEqual(unsigned, self.data)

    def test_separator_can_be_changed(self) -> None:
        """Test that the separator can be changed."""
        separator = b'|'
        signer = Blake2Signer(self.secret, separator=separator)

        signed = signer.sign(self.data)
        self.assertIn(separator, signed)

    def test_sign_unsign_with_b32encoder(self) -> None:
        """Test signing and unsigning using a base32 encoder (non-default)."""
        signer = Blake2Signer(self.secret, encoder=B32Encoder)

        signed = signer.sign(self.data)
        self.assertIsInstance(signed, bytes)
        self.assertRegex(signed.decode(), r'^[A-Z2-7.]+datadata$')

        unsigned = signer.unsign(signed)
        self.assertEqual(self.data, unsigned)


# noinspection PyArgumentEqualDefault
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
            Blake2Signer(
                self.secret,
                digest_size=4,
                hasher=Blake2Signer.Hashers.blake2s,
            )

    def test_digest_too_large(self) -> None:
        """Test digest too large."""
        with self.assertRaises(errors.InvalidOptionError):
            Blake2Signer(self.secret, digest_size=65)

        with self.assertRaises(errors.InvalidOptionError):
            Blake2Signer(
                self.secret,
                digest_size=33,
                hasher=Blake2Signer.Hashers.blake2s,
            )

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

    def test_sign_unsign_wrong_person_same_secret(self) -> None:
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

    def test_wrong_hasher_choice(self) -> None:
        """Test wrong hasher choice."""
        with self.assertRaises(errors.InvalidOptionError):
            Blake2Signer(self.secret, hasher='blake2')

    def test_wrong_separator_in_b64encoder_alphabet(self) -> None:
        """Test error occurs when the separator is in the b64 encoder alphabet."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2Signer(self.secret, separator=b'A', encoder=B64URLEncoder)
        self.assertIn(
            'separator character must not belong to the encoder',
            str(cm.exception),
        )

    def test_wrong_separator_in_b32encoder_alphabet(self) -> None:
        """Test error occurs when the separator is in the b32 encoder alphabet."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2Signer(self.secret, separator=b'A', encoder=B32Encoder)
        self.assertIn(
            'separator character must not belong to the encoder',
            str(cm.exception),
        )

    def test_wrong_separator_non_ascii(self) -> None:
        """Test error occurs when the separator is non-ascii."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2Signer(self.secret, separator=b'\x87')
        self.assertIn('separator character must be ASCII', str(cm.exception))

    def test_wrong_separator_empty(self) -> None:
        """Test error occurs when the separator is empty."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2Signer(self.secret, separator=b'')
        self.assertIn(
            'the separator character must have a value',
            str(cm.exception),
        )


# noinspection PyArgumentEqualDefault
class Blake2TimestampSignerTests(TestCase):
    """Test Blake2TimestampSigner class."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.secret = b'0123456789012345'
        self.data = b'datadata'

    def test_initialisation_defaults(self) -> None:
        """Test correct class defaults initialisation."""
        signer = Blake2TimestampSigner(self.secret)
        self.assertIsInstance(signer, Blake2TimestampSigner)

        signer = Blake2TimestampSigner(
            self.secret,
            hasher=Blake2TimestampSigner.Hashers.blake2s,
        )
        self.assertIsInstance(signer, Blake2TimestampSigner)

    def test_sign(self) -> None:
        """Test signing is correct."""
        signer = Blake2TimestampSigner(self.secret)
        signed = signer.sign(self.data)
        self.assertIsInstance(signed, bytes)
        self.assertEqual(len(signed), 54)

    def test_unsign(self) -> None:
        """Test unsigning is correct."""
        signer = Blake2TimestampSigner(self.secret)
        signed = signer.sign(self.data)
        unsigned = signer.unsign(signed, max_age=timedelta(seconds=1))
        self.assertEqual(unsigned, self.data)

    @mock.patch('blake2signer.bases.time')
    def test_sign_unsign_deterministic(self, mock_time: mock.MagicMock) -> None:
        """Test sign and unsign with a deterministic signature."""
        mock_time.return_value = datetime.now().timestamp()
        signer = Blake2TimestampSigner(self.secret, deterministic=True)

        signed = signer.sign(self.data)
        signed2 = signer.sign(self.data)
        self.assertEqual(signed, signed2)

        unsigned = signer.unsign(signed, max_age=1)
        self.assertEqual(unsigned, self.data)

    @mock.patch('blake2signer.bases.time')
    def test_sign_unsign_nondeterministic(self, mock_time: mock.MagicMock) -> None:
        """Test sign and unsign with a non-deterministic signature (default)."""
        mock_time.return_value = datetime.now().timestamp()
        signer = Blake2TimestampSigner(self.secret, deterministic=False)

        signed = signer.sign(self.data)
        signed2 = signer.sign(self.data)
        self.assertNotEqual(signed, signed2)

        unsigned = signer.unsign(signed, max_age=1)
        self.assertEqual(self.data, unsigned)

        unsigned2 = signer.unsign(signed, max_age=1)
        self.assertEqual(self.data, unsigned2)

    def test_separator_can_be_changed(self) -> None:
        """Test that the separator can be changed."""
        separator = b'|'
        signer = Blake2TimestampSigner(self.secret, separator=separator)

        signed = signer.sign(self.data)
        self.assertIn(separator, signed)

    def test_sign_unsign_with_b32encoder(self) -> None:
        """Test signing and unsigning using a base32 encoder (non-default)."""
        signer = Blake2TimestampSigner(self.secret, encoder=B32Encoder)

        signed = signer.sign(self.data)
        self.assertIsInstance(signed, bytes)
        self.assertRegex(signed.decode(), r'^[A-Z2-7.]+datadata$')

        unsigned = signer.unsign(signed, max_age=1)
        self.assertEqual(self.data, unsigned)


# noinspection PyArgumentEqualDefault
class Blake2TimestampSignerErrorTests(TestCase):
    """Test Blake2TimestampSigner class for errors."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.secret = b'0123456789012345'
        self.data = b'datadata'
        self.signed = (
            b'0n1iOnj6g0q7N-yUGFDG7S3mLt_-8V3kYa09GHLZ5X_HITsstI9vKhkFXly3s6xW'
            b'7gkI0_HHCi8hyRpmoOZH8hUnxcvXMkTrp58QYw.YHd8dA.datadata'
        )
        self.digest_size = 64

    def test_unsign_timestamp_expired(self) -> None:
        """Test unsigning with timestamp is correct."""
        signer = Blake2TimestampSigner(self.secret, digest_size=self.digest_size)
        with self.assertRaises(errors.ExpiredSignatureError):
            signer.unsign(self.signed, max_age=1)

    def test_unsign_wrong_data(self) -> None:
        """Test unsign wrong data."""
        signer = Blake2TimestampSigner(self.secret, digest_size=self.digest_size)
        trick_signer = Blake2Signer(self.secret, digest_size=self.digest_size)
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

    def test_unsign_wrong_timestamped_data(self) -> None:
        """Test unsign wrong timestamped data."""
        signer = Blake2TimestampSigner(self.secret)
        trick_signer = Blake2Signer(self.secret)
        trick_signer._key = signer._key
        trick_signer._person = signer._person

        trick_signed = trick_signer.sign(b'-.' + self.data)
        with self.assertRaises(errors.DecodeError) as exc:
            signer.unsign(trick_signed, max_age=1)
        self.assertIn('can not be decoded', str(exc.exception))

    @mock.patch('blake2signer.bases.time')
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

    def test_wrong_separator_in_b64encoder_alphabet(self) -> None:
        """Test error occurs when the separator is in the b64 encoder alphabet."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2TimestampSigner(self.secret, separator=b'A', encoder=B64URLEncoder)
        self.assertIn(
            'separator character must not belong to the encoder',
            str(cm.exception),
        )

    def test_wrong_separator_in_b32encoder_alphabet(self) -> None:
        """Test error occurs when the separator is in the b32 encoder alphabet."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2TimestampSigner(self.secret, separator=b'A', encoder=B32Encoder)
        self.assertIn(
            'separator character must not belong to the encoder',
            str(cm.exception),
        )

    def test_wrong_separator_non_ascii(self) -> None:
        """Test error occurs when the separator is non-ascii."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2TimestampSigner(self.secret, separator=b'\x87')
        self.assertIn('separator character must be ASCII', str(cm.exception))


# noinspection PyArgumentEqualDefault
class Blake2SerializerSignerTests(TestCase):
    """Test Blake2SerializerSigner class."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.secret = b'0123456789012345'
        self.data = 'datadata'

    def test_initialisation_defaults(self) -> None:
        """Test correct class defaults initialisation."""
        signer = Blake2SerializerSigner(self.secret)
        self.assertIsInstance(signer, Blake2SerializerSigner)

        signer = Blake2SerializerSigner(
            self.secret,
            hasher=Blake2SerializerSigner.Hashers.blake2s,
        )
        self.assertIsInstance(signer, Blake2SerializerSigner)

    def test_initialisation_timestamp(self) -> None:
        """Test correct class defaults with timestamping initialisation."""
        signer = Blake2SerializerSigner(self.secret, max_age=1)
        self.assertIsInstance(signer, Blake2SerializerSigner)

        signer = Blake2SerializerSigner(self.secret, max_age=timedelta(minutes=2))
        self.assertIsInstance(signer, Blake2SerializerSigner)

    def test_dumps_loads_default(self) -> None:
        """Test dumping is correct."""
        signer = Blake2SerializerSigner(self.secret)
        signed = signer.dumps(self.data)
        self.assertIsInstance(signed, str)
        self.assertEqual(len(signed), 53)

        unsigned = signer.loads(signed)
        self.assertEqual(self.data, unsigned)

    def test_dumps_loads_timestamp(self) -> None:
        """Test dumping with timestamp is correct."""
        signer = Blake2SerializerSigner(self.secret, max_age=1)
        signed = signer.dumps(self.data)
        self.assertIsInstance(signed, str)
        self.assertEqual(len(signed), 60)

        unsigned = signer.loads(signed)
        self.assertEqual(self.data, unsigned)

    def test_dumps_loads_compression(self) -> None:
        """Test dumping and loading with compression is correct."""
        signer = Blake2SerializerSigner(self.secret)
        data = self.data * 100  # so compression is meaningful

        signed = signer.dumps(data, use_compression=False)
        signed_compressed = signer.dumps(data, use_compression=True)
        self.assertLessEqual(len(signed_compressed), len(signed))

        signed_compressed = signer.dumps(
            data,
            use_compression=True,
            compression_level=9,
        )
        self.assertLessEqual(len(signed_compressed), len(signed))

        unsigned = signer.loads(signed_compressed)
        self.assertEqual(data, unsigned)

    def test_dumps_loads_auto_compression(self) -> None:
        """Test dumping and loading with auto compression is correct."""
        signer = Blake2SerializerSigner(self.secret)
        data = token_bytes(10).hex()  # so it can't be compressed

        signed = signer.dumps(data, use_compression=False)
        signed_not_compressed = signer.dumps(data, use_compression=True)
        self.assertEqual(len(signed_not_compressed), len(signed))

    def test_dumps_loads_force_compression(self) -> None:
        """Test dumping and loading forcing compression is correct."""
        signer = Blake2SerializerSigner(self.secret)
        data = self.data * 100  # so compression is meaningful

        signed = signer.dumps(data, use_compression=False)
        signed_compressed = signer.dumps(data, force_compression=True)
        self.assertLessEqual(len(signed_compressed), len(signed))

        unsigned = signer.loads(signed_compressed)
        self.assertEqual(data, unsigned)

        # Check force_compression bypasses use_compression
        signed_compressed = signer.dumps(
            data,
            use_compression=False,
            force_compression=True,
        )
        self.assertLessEqual(len(signed_compressed), len(signed))

    def test_dumps_loads_other_options(self) -> None:
        """Test dumping with other options is correct."""
        signer = Blake2SerializerSigner(
            self.secret,
            max_age=1,
            personalisation=b'acab',
            hasher=Blake2SerializerSigner.Hashers.blake2s,
            digest_size=24,
        )
        self.assertIsInstance(signer, Blake2SerializerSigner)

        unsigned = signer.loads(signer.dumps(self.data))
        self.assertEqual(self.data, unsigned)

        unsigned = signer.loads(signer.dumps(self.data, use_compression=True))
        self.assertEqual(self.data, unsigned)

    def test_dumps_loads_with_custom_serializer(self) -> None:  # noqa: C901
        """Test dumping using a custom serializer."""

        class MyObject:
            """Some object."""

            def __init__(self):
                self.a = None

            def __str__(self):
                return self.a  # pragma: no cover

        class CustomJSONEncoder(json.JSONEncoder):
            """Custom JSON encoder."""

            def default(self, o):
                """Encode object."""
                if isinstance(o, MyObject):
                    return str(o.a)

                return super().default(o)  # pragma: no cover

        class MyJSONSerializer(JSONSerializer):
            """Custom JSON serializer."""

            def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
                """Serialize data."""
                return super().serialize(data, cls=CustomJSONEncoder, **kwargs)

        obj = MyObject()
        obj.a = 'acab'

        signer = Blake2SerializerSigner(self.secret, serializer=MyJSONSerializer)

        unsigned = signer.loads(signer.dumps(obj))
        self.assertEqual(obj.a, unsigned)

    def test_dumps_loads_deterministic(self) -> None:
        """Test dumps and loads with a deterministic signature."""
        signer = Blake2SerializerSigner(self.secret, deterministic=True)

        signed = signer.dumps(self.data)
        signed2 = signer.dumps(self.data)
        self.assertEqual(signed, signed2)

        unsigned = signer.loads(signed)
        self.assertEqual(unsigned, self.data)

    def test_dumps_loads_nondeterministic(self) -> None:
        """Test dumps and loads with a non-deterministic signature (default)."""
        signer = Blake2SerializerSigner(self.secret, deterministic=False)

        signed = signer.dumps(self.data)
        signed2 = signer.dumps(self.data)
        self.assertNotEqual(signed, signed2)

        unsigned = signer.loads(signed)
        self.assertEqual(self.data, unsigned)

        unsigned2 = signer.loads(signed)
        self.assertEqual(self.data, unsigned2)

    def test_dumps_loads_with_b64encoder(self) -> None:
        """Test dumping and loading using a base64 URL safe  encoder (default)."""
        signer = Blake2SerializerSigner(self.secret, encoder=B64URLEncoder)
        signed = signer.dumps(self.data)
        self.assertIsInstance(signed, str)
        self.assertRegex(signed, r'^[a-zA-Z0-9_\-.]+$')

        unsigned = signer.loads(signed)
        self.assertEqual(self.data, unsigned)

    def test_separator_can_be_changed(self) -> None:
        """Test that the separator can be changed."""
        separator = b'|'
        signer = Blake2SerializerSigner(self.secret, separator=separator)

        signed = signer.dumps(self.data)
        self.assertIn(separator.decode(), signed)

    def test_compression_flag_can_be_changed(self) -> None:
        """Test that the compression flag can be changed."""
        flag = b'|'
        data = self.data * 10  # Ensure compressibility
        signer = Blake2SerializerSigner(self.secret, compression_flag=flag)

        signed = signer.dumps(data)
        unsigned = signer._loads(signed.encode())
        undecoded = signer._decode(unsigned)
        self.assertIn(flag, undecoded)
        self.assertTrue(undecoded.startswith(flag))

    def test_compression_ratio_can_be_changed(self) -> None:
        """Test that the compression flag can be changed."""
        data = 'datadatadatadata'  # Only somewhat compressible
        signer1 = Blake2SerializerSigner(self.secret, compression_ratio=10)
        signer2 = Blake2SerializerSigner(self.secret, compression_ratio=20)

        signed1 = signer1.dumps(data)  # Compressed
        signed2 = signer2.dumps(data)  # Not compressed

        self.assertLess(len(signed1), len(signed2))

    def test_string_instead_of_bytes_inputs(self) -> None:
        """Test non-bytes values for parameters such as secret, person, data, etc."""
        secret = self.secret.decode()
        signer = Blake2SerializerSigner(
            secret,
            personalisation='person',
            separator=',',
            compression_flag='!',
        )

        signed = signer.dumps(self.data)
        self.assertIsInstance(signed, str)

        unsigned = signer.loads(signed.encode())
        self.assertIsInstance(unsigned, str)
        self.assertEqual(unsigned, self.data)

    def test_dumps_loads_with_b32encoder(self) -> None:
        """Test dumping and loading using a base32 encoder (non-default)."""
        signer = Blake2SerializerSigner(self.secret, encoder=B32Encoder)
        signed = signer.dumps(self.data)
        self.assertIsInstance(signed, str)
        self.assertRegex(signed, r'^[A-Z2-7.]+$')

        unsigned = signer.loads(signed)
        self.assertEqual(self.data, unsigned)


# noinspection PyArgumentEqualDefault
class Blake2SerializerSignerErrorTests(TestCase):
    """Test Blake2SerializerSigner class for errors."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.secret = b'0123456789012345'
        self.data = 'datadata'
        self.dumped = '7e6gbEh_vwnZFwoB45yKH-lCEXgC-EWr6d5DkA.YHd85A.ImRhdGFkYXRhIg'

    def test_secret_too_short(self) -> None:
        """Test parameters out of bounds."""
        with self.assertRaises(errors.InvalidOptionError):
            Blake2SerializerSigner(b'12345678')

    def test_signature_too_short(self) -> None:
        """Test parameters out of bounds."""
        with self.assertRaises(errors.InvalidOptionError):
            Blake2SerializerSigner(self.secret, digest_size=4)

    def test_loads_timestamp_expired(self) -> None:
        """Test loading with timestamp is correct."""
        signer = Blake2SerializerSigner(self.secret, max_age=1)

        with self.assertRaises(errors.ExpiredSignatureError):
            signer.loads(self.dumped)

    def test_dumps_wrong_data(self) -> None:
        """Test dumps wrong data."""
        signer = Blake2SerializerSigner(self.secret)

        with self.assertRaises(errors.SerializationError) as cm:  # `msg` doesn't work
            signer.dumps(b'datadata')  # any non JSON encodable type
        self.assertEqual(
            str(cm.exception),
            'Object of type bytes is not JSON serializable',
        )

    def test_loads_wrong_data(self) -> None:
        """Test loads wrong data."""
        signer = Blake2SerializerSigner(self.secret)
        with self.assertRaises(errors.ConversionError) as cm:
            # noinspection PyTypeChecker
            signer.loads(1.0)  # type: ignore
        self.assertEqual(str(cm.exception), 'value can not be converted to bytes')

    def test_loads_b64decode_error(self) -> None:
        """Test loads wrong data causing base64 decoding error."""
        signer = Blake2SerializerSigner(self.secret)
        trick_signed = signer._sign(b'-')  # some non-base64 char

        with self.assertRaises(errors.DecodeError) as cm:
            signer.loads(trick_signed)
        self.assertEqual(str(cm.exception), 'data can not be decoded')

    def test_loads_decompression_error(self) -> None:
        """Test loads wrong data causing decompression error."""
        signer = Blake2SerializerSigner(self.secret)
        trick_signed = signer._sign(
            b64encode(signer._compression_flag + b'a'),  # trick into decompression
        )

        with self.assertRaises(errors.DecompressionError) as cm:
            signer.loads(trick_signed)
        self.assertEqual(str(cm.exception), 'data can not be decompressed')

    def test_loads_unserialization_error(self) -> None:
        """Test loads wrong data causing unserialization error."""
        signer = Blake2SerializerSigner(self.secret)
        trick_signed = signer._sign(b'data')  # non-serializable data

        with self.assertRaises(errors.UnserializationError) as cm:
            signer.loads(trick_signed)
        self.assertEqual(str(cm.exception), 'data can not be unserialized')

    @mock.patch('blake2signer.compressors.zlib.compress')
    def test_dumps_compression_error(self, mock_zlib_compress: mock.MagicMock) -> None:
        """Test compression error while dumping."""
        mock_zlib_compress.side_effect = zlib.error

        signer = Blake2SerializerSigner(self.secret)

        with self.assertRaises(errors.CompressionError):
            signer.dumps(self.data, use_compression=True)

    @mock.patch('blake2signer.encoders.b64encode')
    def test_dumps_encoding_error(self, mock_b64encode: mock.MagicMock) -> None:
        """Test encoding error while dumping."""
        mock_b64encode.side_effect = ValueError

        signer = Blake2SerializerSigner(self.secret)

        with self.assertRaises(errors.EncodeError):
            signer.dumps(self.data)

    def test_dumps_invalid_compression_level(self) -> None:
        """Test invalid compression level for dumps."""
        signer = Blake2SerializerSigner(self.secret)

        with self.assertRaises(errors.CompressionError):
            signer.dumps(self.data, use_compression=True, compression_level=10)

    def test_wrong_separator_in_b64encoder_alphabet(self) -> None:
        """Test error occurs when the separator is in the b64 encoder alphabet."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2SerializerSigner(self.secret, separator=b'A', encoder=B64URLEncoder)
        self.assertIn(
            'separator character must not belong to the encoder',
            str(cm.exception),
        )

    def test_wrong_separator_in_b32encoder_alphabet(self) -> None:
        """Test error occurs when the separator is in the b32 encoder alphabet."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2SerializerSigner(self.secret, separator=b'A', encoder=B32Encoder)
        self.assertIn(
            'separator character must not belong to the encoder',
            str(cm.exception),
        )

    def test_wrong_separator_non_ascii(self) -> None:
        """Test error occurs when the separator is non-ascii."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2SerializerSigner(self.secret, separator=b'\x87')
        self.assertIn('separator character must be ASCII', str(cm.exception))

    def test_wrong_compression_flag_non_ascii(self) -> None:
        """Test error occurs when the compression flag is non-ascii."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2SerializerSigner(self.secret, compression_flag=b'\x87')
        self.assertIn('compression flag character must be ASCII', str(cm.exception))

    def test_wrong_compression_ratio(self) -> None:
        """Test error occurs when the compression ratio is out of bounds."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2SerializerSigner(self.secret, compression_ratio=-1)
        self.assertIn('compression ratio must be', str(cm.exception))

        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2SerializerSigner(self.secret, compression_ratio=100)
        self.assertIn('compression ratio must be', str(cm.exception))

    def test_wrong_compression_flag_empty(self) -> None:
        """Test error occurs when the compression flag is empty."""
        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2SerializerSigner(self.secret, compression_flag=b'')
        self.assertIn(
            'the compression flag character must have a value',
            str(cm.exception),
        )

    def test_wrong_encoder_non_ascii_alphabet(self) -> None:
        """Test encoder having a non-ASCII alphabet raises exception."""

        class Encoder(EncoderInterface):
            """Wrong encoder."""

            @property
            def alphabet(self) -> bytes:
                """Get encoder alphabet."""
                return b'\x87'

            def encode(self, data: typing.AnyStr) -> bytes:
                """Encode data."""
                pass  # pragma: nocover

            def decode(self, data: typing.AnyStr) -> bytes:
                """Decode data."""
                pass  # pragma: nocover

        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2SerializerSigner(self.secret, encoder=Encoder)
        self.assertIn('encoder alphabet must be ASCII', str(cm.exception))

    def test_wrong_encoder_empty_alphabet(self) -> None:
        """Test encoder having an empty alphabet raises exception."""

        class Encoder(EncoderInterface):
            """Wrong encoder."""

            @property
            def alphabet(self) -> bytes:
                """Get encoder alphabet."""
                return b''

            def encode(self, data: typing.AnyStr) -> bytes:
                """Encode data."""
                pass  # pragma: nocover

            def decode(self, data: typing.AnyStr) -> bytes:
                """Decode data."""
                pass  # pragma: nocover

        with self.assertRaises(errors.InvalidOptionError) as cm:
            Blake2SerializerSigner(self.secret, encoder=Encoder)
        self.assertIn('encoder alphabet must have a value', str(cm.exception))
