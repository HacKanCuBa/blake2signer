"""Serializers module tests."""

import json
import typing
import zlib
from datetime import timedelta
from secrets import token_bytes
from unittest import TestCase
from unittest import mock

from .. import errors
from ..serializers import Blake2SerializerSigner
from ..serializers import JSONSerializer
from ..utils import b64encode


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

    def test_dumps_loads_with_custom_encoder(self) -> None:  # noqa: C901
        """Test dumping using a custom encoder."""

        class MyObject:

            def __init__(self):
                self.a = None

            def __str__(self):
                return self.a  # pragma: no cover

        class CustomJSONEncoder(json.JSONEncoder):

            def default(self, o):
                if isinstance(o, MyObject):
                    return str(o.a)

                return super().default(o)  # pragma: no cover

        class MyJSONSerializer(JSONSerializer):

            def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
                return super().serialize(data, cls=CustomJSONEncoder, **kwargs)

        obj = MyObject()
        obj.a = 'acab'

        signer = Blake2SerializerSigner(self.secret, serializer=MyJSONSerializer)

        unsigned = signer.loads(signer.dumps(obj))
        self.assertEqual(obj.a, unsigned)


class Blake2SerializerSignerErrorTests(TestCase):
    """Test Blake2SerializerSigner class for errors."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.secret = b'0123456789012345'
        self.data = 'datadata'
        self.dumped = 'AuPHEW7PazR4UB7jmt20GvhunB6KNVXbEzUaOA.X4OovQ.ImRhdGFkYXRhIg'

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
            b64encode(signer.COMPRESSION_FLAG + b'a'),  # trick into decompression
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

    @mock.patch('blake2signer.serializers.zlib.compress')
    def test_dumps_compression_error(self, mock_zlib_compress: mock.MagicMock) -> None:
        """Test compression error while dumping."""
        mock_zlib_compress.side_effect = zlib.error

        signer = Blake2SerializerSigner(self.secret)

        with self.assertRaises(errors.CompressionError):
            signer.dumps(self.data, use_compression=True)

    @mock.patch('blake2signer.serializers.b64encode')
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
