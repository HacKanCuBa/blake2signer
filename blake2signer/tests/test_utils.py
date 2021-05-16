"""Utils module tests."""

import io
from datetime import datetime

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
    assert timestamp == int(converted_timestamp.timestamp())


def test_timestamp_to_aware_datetime_accepts_float() -> None:
    """Test timestamp_to_aware_datetime accepts float timestamps."""
    timestamp = 1619064799.965
    converted_timestamp = utils.timestamp_to_aware_datetime(timestamp)

    assert isinstance(converted_timestamp, datetime)
    assert timestamp == converted_timestamp.timestamp()


def test_file_mode_is_text() -> None:
    """Test file_mode_is_text works correctly."""
    text_file = io.StringIO()
    assert utils.file_mode_is_text(text_file)

    bin_file = io.BytesIO()
    assert not utils.file_mode_is_text(bin_file)
