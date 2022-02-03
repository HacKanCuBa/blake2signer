"""Utils module tests."""

import io
from datetime import datetime
from datetime import timedelta

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
