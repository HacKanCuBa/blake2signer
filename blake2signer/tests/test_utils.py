"""Utils module tests."""

import io
from datetime import datetime
from unittest import TestCase

from .. import utils


class TestUtils(TestCase):
    """Test the utils module."""

    def test_b64encode_strips_padding(self) -> None:
        """Test b64encode strips padding correctly."""
        encoded = utils.b64encode(b'abcd')
        self.assertEqual(encoded, b'YWJjZA')

        encoded = utils.b64encode(b'abc')
        self.assertEqual(encoded, b'YWJj')

    def test_b64decode_stripped_padding_works(self) -> None:
        """Test b64decode works without padding."""
        decoded = utils.b64decode(b'YWJjZA')
        self.assertEqual(decoded, b'abcd')

        decoded = utils.b64decode(b'YWJj')
        self.assertEqual(decoded, b'abc')

    def test_b64decode_works_with_padding(self) -> None:
        """Test b64decode accepts padded value correctly."""
        decoded = utils.b64decode(b'YWJj==')
        self.assertEqual(decoded, b'abc')

    def test_b32encode_strips_padding(self) -> None:
        """Test b32encode strips padding correctly."""
        encoded = utils.b32encode(b'abcd')
        self.assertEqual(encoded, b'MFRGGZA')

        encoded = utils.b32encode(b'abc')
        self.assertEqual(encoded, b'MFRGG')

    def test_b32decode_stripped_padding_works(self) -> None:
        """Test b32decode works without padding."""
        decoded = utils.b32decode(b'MFRGGZA')
        self.assertEqual(decoded, b'abcd')

        decoded = utils.b32decode(b'MFRGG')
        self.assertEqual(decoded, b'abc')

    def test_b32decode_works_with_padding(self) -> None:
        """Test b32decode accepts padded value correctly."""
        decoded = utils.b32decode(b'MFRGG===')
        self.assertEqual(decoded, b'abc')

    def test_hexdecode_accepts_bytes(self) -> None:
        """Test hexdecode accepts bytes correctly."""
        decoded = utils.hexdecode(b'616263')
        self.assertEqual(decoded, b'abc')

    def test_hexencode_accepts_bytes(self) -> None:
        """Test hexencode accepts bytes correctly."""
        encoded = utils.hexencode(b'abc')
        self.assertEqual(encoded, b'616263')

    def test_timestamp_to_aware_datetime_accepts_int(self) -> None:
        """Test timestamp_to_aware_datetime accepts int timestamps."""
        timestamp = 1619064799
        converted_timestamp = utils.timestamp_to_aware_datetime(timestamp)

        self.assertIsInstance(converted_timestamp, datetime)
        self.assertEqual(timestamp, int(converted_timestamp.timestamp()))

    def test_timestamp_to_aware_datetime_accepts_float(self) -> None:
        """Test timestamp_to_aware_datetime accepts float timestamps."""
        timestamp = 1619064799.965
        converted_timestamp = utils.timestamp_to_aware_datetime(timestamp)

        self.assertIsInstance(converted_timestamp, datetime)
        self.assertEqual(timestamp, converted_timestamp.timestamp())

    def test_file_mode_is_text(self) -> None:
        """Test file_mode_is_text works correctly."""
        text_file = io.StringIO()
        self.assertTrue(utils.file_mode_is_text(text_file))

        bin_file = io.BytesIO()
        self.assertFalse(utils.file_mode_is_text(bin_file))
