"""Serializers module tests."""

import json
import zlib
from datetime import timedelta
from unittest import TestCase
from unittest import mock

from ..errors import DecodeError
from ..errors import EncodeError
from ..errors import ExpiredSignatureError
from ..errors import InvalidOptionError
from ..serializers import Blake2Serializer


class Blake2SerializerTests(TestCase):
    """Test Blake2Serializer class."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.secret = b'0123456789012345'
        self.data = 'datadata'

    def test_initialisation_defaults(self) -> None:
        """Test correct class defaults initialisation."""
        signer = Blake2Serializer(self.secret)
        self.assertIsInstance(signer, Blake2Serializer)

        signer = Blake2Serializer(self.secret, hasher=Blake2Serializer.Hashers.blake2s)
        self.assertIsInstance(signer, Blake2Serializer)

    def test_initialisation_timestamp(self) -> None:
        """Test correct class defaults with timestamping initialisation."""
        signer = Blake2Serializer(self.secret, max_age=1)
        self.assertIsInstance(signer, Blake2Serializer)

        signer = Blake2Serializer(self.secret, max_age=timedelta(minutes=2))
        self.assertIsInstance(signer, Blake2Serializer)

    def test_dumps_loads_default(self) -> None:
        """Test dumping is correct."""
        signer = Blake2Serializer(self.secret)
        signed = signer.dumps(self.data)
        self.assertIsInstance(signed, str)
        self.assertEqual(len(signed), 56)

        unsigned = signer.loads(signed)
        self.assertEqual(self.data, unsigned)

    def test_dumps_loads_timestamp(self) -> None:
        """Test dumping with timestamp is correct."""
        signer = Blake2Serializer(self.secret, max_age=1)
        signed = signer.dumps(self.data)
        self.assertIsInstance(signed, str)
        self.assertEqual(len(signed), 62)

        unsigned = signer.loads(signed)
        self.assertEqual(self.data, unsigned)

    def test_dumps_loads_compression(self) -> None:
        """Test dumping and loading with compression is correct."""
        signer = Blake2Serializer(self.secret)
        data = self.data * 100  # so compression is meaningful

        signed = signer.dumps(data, use_compression=False)
        signed_compressed = signer.dumps(data, use_compression=True)
        self.assertLessEqual(len(signed_compressed), len(signed))

        unsigned = signer.loads(signed_compressed)
        self.assertEqual(data, unsigned)

    def test_dumps_loads_other_options(self) -> None:
        """Test dumping with other options is correct."""
        signer = Blake2Serializer(
            self.secret,
            max_age=1,
            person=b'acab',
            hasher=Blake2Serializer.Hashers.blake2s,
            digest_size=10,
        )
        self.assertIsInstance(signer, Blake2Serializer)

        unsigned = signer.loads(signer.dumps(self.data))
        self.assertEqual(self.data, unsigned)

        unsigned = signer.loads(signer.dumps(self.data, use_compression=True))
        self.assertEqual(self.data, unsigned)

    def test_dumps_loads_with_custom_encoder(self) -> None:
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

        obj = MyObject()
        obj.a = 'acab'

        signer = Blake2Serializer(self.secret, json_encoder=CustomJSONEncoder)

        unsigned = signer.loads(signer.dumps(obj))
        self.assertEqual(obj.a, unsigned)


class Blake2SerializerErrorTests(TestCase):
    """Test Blake2Serializer class for errors."""

    def setUp(self) -> None:
        """Set up test cases."""
        self.secret = b'0123456789012345'
        self.data = 'datadata'

    def test_secret_too_short(self) -> None:
        """Test parameters out of bounds."""
        with self.assertRaises(InvalidOptionError):
            Blake2Serializer(b'12345678')

    def test_signature_too_short(self) -> None:
        """Test parameters out of bounds."""
        with self.assertRaises(InvalidOptionError):
            Blake2Serializer(b'01234567890123456789', digest_size=4)

    def test_loads_timestamp_expired(self) -> None:
        """Test loading with timestamp is correct."""
        from time import sleep

        timeout = 0.00001
        signer = Blake2Serializer(self.secret, max_age=timeout)
        signed = signer.dumps(self.data)
        sleep(timeout)
        with self.assertRaises(ExpiredSignatureError):
            signer.loads(signed)

    def test_dumps_wrong_data(self) -> None:
        """Test sign wrong data."""
        signer = Blake2Serializer(self.secret)
        with self.assertRaises(EncodeError):
            signer.dumps(b'datadata')  # any non JSON encodable type

    def test_loads_wrong_data(self) -> None:
        """Test unsign wrong data."""
        signer = Blake2Serializer(self.secret)
        with self.assertRaises(DecodeError):
            # noinspection PyTypeChecker
            signer.loads(1234)  # type: ignore

    @mock.patch('blake2signer.serializers.zlib.decompress')
    def test_loads_decompression_error(self, mock_decompress: mock.MagicMock) -> None:
        """Test unsign wrong data causing decompression error."""
        mock_decompress.side_effect = zlib.error

        signer = Blake2Serializer(self.secret)
        signed = signer.dumps(self.data, use_compression=True)

        with self.assertRaises(DecodeError):
            signer.loads(signed)

    @mock.patch('blake2signer.serializers.json.loads')
    def test_loads_unserialization_error(self, mock_loads: mock.MagicMock) -> None:
        """Test unsign wrong data causing unserialization error."""
        mock_loads.side_effect = ValueError

        signer = Blake2Serializer(self.secret)
        signed = signer.dumps(self.data, use_compression=True)

        with self.assertRaises(DecodeError):
            signer.loads(signed)

    @mock.patch('blake2signer.serializers.zlib.compress')
    def test_dumps_compression_error(self, mock_zlib_compress: mock.MagicMock) -> None:
        """Test compression error while dumping."""
        mock_zlib_compress.side_effect = zlib.error

        signer = Blake2Serializer(self.secret)

        with self.assertRaises(EncodeError):
            signer.dumps(self.data, use_compression=True)

    @mock.patch('blake2signer.serializers.b64encode')
    def test_dumps_encoding_error(self, mock_b64encode: mock.MagicMock) -> None:
        """Test encoding error while dumping."""
        mock_b64encode.side_effect = ValueError

        signer = Blake2Serializer(self.secret)

        with self.assertRaises(EncodeError):
            signer.dumps(self.data)
