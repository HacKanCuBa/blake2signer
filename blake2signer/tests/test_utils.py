"""Utils module tests."""

import io
import typing
from datetime import datetime
from datetime import timedelta
from unittest import mock

import pytest

from .. import utils


def test_b64encode_strips_padding() -> None:
    """Test b64encode strips padding correctly."""
    encoded = utils.b64encode(b'abcd')
    assert encoded == b'YWJjZA'

    encoded = utils.b64encode(b'abc')
    assert encoded == b'YWJj'


def test_b64decode_stripped_padding_works() -> None:
    """Test b64decode works without padding."""
    decoded = utils.b64decode(b'YWJjZA')
    assert decoded == b'abcd'

    decoded = utils.b64decode(b'YWJj')
    assert decoded == b'abc'


def test_b64decode_works_with_padding() -> None:
    """Test b64decode accepts padded value correctly."""
    decoded = utils.b64decode(b'YWJj==')
    assert decoded == b'abc'


def test_b32encode_strips_padding() -> None:
    """Test b32encode strips padding correctly."""
    encoded = utils.b32encode(b'abcd')
    assert encoded == b'MFRGGZA'

    encoded = utils.b32encode(b'abc')
    assert encoded == b'MFRGG'


def test_b32decode_stripped_padding_works() -> None:
    """Test b32decode works without padding."""
    decoded = utils.b32decode(b'MFRGGZA')
    assert decoded == b'abcd'

    decoded = utils.b32decode(b'MFRGG')
    assert decoded == b'abc'


def test_b32decode_works_with_padding() -> None:
    """Test b32decode accepts padded value correctly."""
    decoded = utils.b32decode(b'MFRGG===')
    assert decoded == b'abc'


def test_hexdecode_accepts_bytes() -> None:
    """Test hexdecode accepts bytes correctly."""
    decoded = utils.hexdecode(b'616263')
    assert decoded == b'abc'


def test_hexencode_accepts_bytes() -> None:
    """Test hexencode accepts bytes correctly."""
    encoded = utils.hexencode(b'abc')
    assert encoded == b'616263'


def test_b58decode_works() -> None:
    """Test b58decode works correctly."""
    decoded = utils.b58decode(b'ZiCa')
    assert decoded == b'abc'


def test_b58decode_adds_leading_zeroes() -> None:
    """Test b58decode adds leading zeroes correctly."""
    decoded = utils.b58decode(b'111ZiCa')
    assert decoded == b'\x00\x00\x00abc'


def test_b58decode_fails_unknown_char() -> None:
    """Test b58decode fails when unknown char is passed."""
    with pytest.raises(KeyError, match=str(int.from_bytes(b'I', 'big'))):
        utils.b58decode(b'abcI')


def test_b58encode_works() -> None:
    """Test b58encode works correctly."""
    encoded = utils.b58encode(b'abc')
    assert encoded == b'ZiCa'

    # Test vectors from "The Base58 Encoding Scheme"
    # https://datatracker.ietf.org/doc/html/draft-msporny-base58#page-6
    encoded = utils.b58encode(b'Hello World!')
    assert encoded == b'2NEpo7TZRRrLZSi2U'

    encoded = utils.b58encode(b'The quick brown fox jumps over the lazy dog.')
    assert encoded == b'USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z'

    num = 0x0000287fb4cd
    encoded = utils.b58encode(num.to_bytes(2 + (num.bit_length() + 7) // 8, 'big'))
    assert encoded == b'11233QC4'


def test_b58encode_encodes_leading_zeroes() -> None:
    """Test b58encode encodes leading zeroes correctly."""
    encoded = utils.b58encode(b'\x00\x00\x00abc')
    assert encoded == b'111ZiCa'


def test_timestamp_to_aware_datetime_accepts_int() -> None:
    """Test timestamp_to_aware_datetime accepts int timestamps."""
    timestamp = 1619064799
    converted_timestamp = utils.timestamp_to_aware_datetime(timestamp)

    assert isinstance(converted_timestamp, datetime)
    assert timedelta() == converted_timestamp.utcoffset()  # Aware in UTC
    # Technically, Python does some coercing, as in (1 == 1.0) is True, but just in case:
    assert timestamp == int(converted_timestamp.timestamp())
    assert float(timestamp) == converted_timestamp.timestamp()
    assert timestamp == converted_timestamp.timestamp()


def test_timestamp_to_aware_datetime_accepts_float() -> None:
    """Test timestamp_to_aware_datetime accepts float timestamps."""
    timestamp = 1619064799.965
    converted_timestamp = utils.timestamp_to_aware_datetime(timestamp)

    assert isinstance(converted_timestamp, datetime)
    assert timedelta() == converted_timestamp.utcoffset()  # Aware in UTC
    assert timestamp == converted_timestamp.timestamp()


def test_file_mode_is_text() -> None:
    """Test file_mode_is_text works correctly."""
    text_file = io.StringIO()
    assert utils.file_mode_is_text(text_file)

    bin_file = io.BytesIO()
    assert not utils.file_mode_is_text(bin_file)


def test_ordinal() -> None:
    """Test that the ordinal function works correctly."""
    assert '0th' == utils.ordinal(0)
    assert '1st' == utils.ordinal(1)
    assert '2nd' == utils.ordinal(2)
    assert '3rd' == utils.ordinal(3)
    assert '4th' == utils.ordinal(4)
    assert '12th' == utils.ordinal(12)
    assert '100th' == utils.ordinal(100)
    assert '101st' == utils.ordinal(101)
    assert '1003rd' == utils.ordinal(1003)


@pytest.mark.parametrize(
    ('value', 'expected'),
    (
        (b'abc', b'abc'),
        ('abc', b'abc'),
    ),
)
def test_force_bytes(value: typing.Any, expected: str) -> None:
    """Test that force_bytes works correctly."""
    forced = utils.force_bytes(value)

    assert isinstance(forced, bytes)
    assert expected == forced


def test_force_bytes_wrong_type() -> None:
    """Test that force_bytes raises exception on a wrong type."""
    with pytest.raises(TypeError, match='value must be bytes or str'):
        utils.force_bytes(1)  # type: ignore


@pytest.mark.parametrize(
    ('value', 'expected'),
    (
        (b'abc', 'abc'),
        ('abc', 'abc'),
    ),
)
def test_force_string(value: typing.Any, expected: str) -> None:
    """Test that force_string works correctly."""
    forced = utils.force_string(value)

    assert isinstance(forced, str)
    assert expected == forced


def test_force_string_wrong_type() -> None:
    """Test that force_string raises exception on a wrong type."""
    with pytest.raises(TypeError, match='value must be bytes or str'):
        utils.force_string(1)  # type: ignore


def test_get_current_time() -> None:
    """Test that get_current_time returns the result of `time.time()`."""
    now = 1709782484.3680992

    with mock.patch.object(utils, 'time', return_value=now) as mock_time:
        assert now == utils.get_current_time()

        mock_time.assert_called_once_with()


def test_generate_secret() -> None:
    """Test that generate_secret returns a value.

    We are not checking entropy nor anything like that, it would be pointless.
    """
    key = utils.generate_secret()

    assert isinstance(key, str)
    assert key  # Assert we have a value
