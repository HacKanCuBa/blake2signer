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

    def test_b64decode_accepts_strings(self) -> None:
        """Test b64decode accepts strings correctly."""
        decoded = utils.b64decode('YWJj')
        self.assertEqual(decoded, b'abc')

    def test_b64encode_accepts_strings(self) -> None:
        """Test b64encode accepts strings correctly."""
        encoded = utils.b64encode('abc')
        self.assertEqual(encoded, b'YWJj')

    def test_b64decode_works_with_padding(self) -> None:
        """Test b64decode accepts padded value correctly."""
        decoded = utils.b64decode(b'YWJj==')
        self.assertEqual(decoded, b'abc')
