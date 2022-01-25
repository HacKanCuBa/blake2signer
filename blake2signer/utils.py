"""Miscellaneous utilities."""

import base64
import io
import typing
from datetime import datetime
from datetime import timezone


def force_bytes(value: typing.Any) -> bytes:
    """Force a given value into bytes.

    Args:
        value: Value to convert to bytes.

    Returns:
        Converted value into bytes.
    """
    if isinstance(value, bytes):
        return value
    elif isinstance(value, str):
        return value.encode('utf-8', errors='strict')

    return bytes(value)


def b64encode(data: bytes) -> bytes:
    """Encode data as Base 64 URL safe, stripping padding.

    Args:
        data: Data to encode.

    Returns:
        Encoded data.
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def b64decode(data: bytes) -> bytes:
    """Decode data encoded as Base 64 URL safe without padding.

    Args:
        data: Data to decode.

    Returns:
        Original data.
    """
    return base64.urlsafe_b64decode(data + (b'=' * (len(data) % 4)))


def b32encode(data: bytes) -> bytes:
    """Encode data as Base 32, stripping padding.

    Args:
        data: Data to encode.

    Returns:
        Encoded data.
    """
    return base64.b32encode(data).rstrip(b'=')


def b32decode(data: bytes) -> bytes:
    """Decode data encoded as Base 32 without padding.

    Args:
        data: Data to decode.

    Returns:
        Original data.
    """
    return base64.b32decode(data + (b'=' * ((8 - (len(data) % 8)) % 8)))


def hexencode(data: bytes) -> bytes:
    """Encode data as hexadecimal (uppercase).

    Args:
        data: Data to encode.

    Returns:
        Encoded data.
    """
    return base64.b16encode(data)


def hexdecode(data: bytes) -> bytes:
    """Decode data encoded as hexadecimal (uppercase).

    Args:
        data: Data to decode.

    Returns:
        Original data.
    """
    return base64.b16decode(data)


def timestamp_to_aware_datetime(timestamp: typing.Union[int, float]) -> datetime:
    """Convert a UNIX timestamp into an aware datetime in UTC.

    Args:
        timestamp: UNIX timestamp to convert.

    Returns:
        Converted timestamp into an aware datetime in UTC.
    """
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def file_mode_is_text(file: typing.IO) -> bool:
    """Check if given file is opened in text mode, or otherwise in binary mode.

    Args:
        file: File to check its mode.

    Returns:
        True if file is opened in text mode, False otherwise.
    """
    # Is there a better way to determine this? I thought on reading one byte/char,
    # then checking the type, but the file might be writable only, so it wouldn't
    # work.
    return isinstance(file, io.TextIOBase)


def ordinal(number: int) -> str:
    """Convert an integer into its ordinal representation.

    Args:
        number: integer number to get its ordinal representation.

    Returns:
        The ordinal string representation of the number as the number + ordinal suffix.

    Examples:
        >>> ordinal(0)
        '0th'
        >>> ordinal(3)
        '3rd'
    """
    # From https://stackoverflow.com/a/50992575
    if 11 <= (number % 100) <= 13:
        suffix = 'th'
    else:
        suffixes = ('th', 'st', 'nd', 'rd', 'th')
        idx = min(number % 10, 4)
        suffix = suffixes[idx]

    return f'{number}{suffix}'
