"""Utils module tests."""

from unittest import TestCase

from .. import utils


class TestUtilsBase64(TestCase):

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
