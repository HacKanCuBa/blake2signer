"""Miscellaneous utilities."""

import base64
import io
import typing as t
from datetime import datetime
from datetime import timezone
from functools import lru_cache
from secrets import token_bytes
from time import time

B58_ALPHABET: t.Final[bytes] = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def force_bytes(value: t.Union[str, bytes]) -> bytes:
    """Force a given value into bytes.

    Args:
        value: Value to convert to bytes.

    Returns:
        Converted value into bytes.

    Raises:
        TypeError: Value is neither bytes nor string.
    """
    if isinstance(value, bytes):
        return value

    if isinstance(value, str):
        return value.encode('utf-8', errors='strict')

    raise TypeError('value must be bytes or str')


def force_string(value: t.Union[str, bytes]) -> str:
    """Force a given value into string.

    Args:
        value: Value to convert to string.

    Returns:
        Converted value into string.

    Raises:
        TypeError: Value is neither bytes nor string.
    """
    if isinstance(value, str):
        return value

    if isinstance(value, bytes):
        return value.decode('utf-8', errors='strict')

    raise TypeError('value must be bytes or str')


def b64encode(data: bytes) -> bytes:
    """Encode data as Base 64 URL-safe, stripping padding.

    Args:
        data: Data to encode.

    Returns:
        Encoded data.
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def b64decode(data: bytes) -> bytes:
    """Decode data encoded as Base 64 URL-safe without padding.

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


def b58encode(data: bytes) -> bytes:
    """Encode data as Base 58.

    Base 58 has no padding, and it contains characters from a-z (except l), A-Z (except I and O),
    and numbers 1-9, to improve readability and reduce transcription errors.

    Args:
        data: Data to encode.

    Returns:
        Encoded data.
    """
    scrubbed_data = data.lstrip(b'\x00')
    num = int.from_bytes(scrubbed_data, 'big')
    base = len(B58_ALPHABET)
    encoded = []

    while num > 0:
        num, rem = divmod(num, base)
        encoded.append(B58_ALPHABET[rem:rem + 1])

    encoded.reverse()

    leading_zeroes_as_first_char = B58_ALPHABET[0:1] * (len(data) - len(scrubbed_data))

    return leading_zeroes_as_first_char + b''.join(encoded)


@lru_cache(maxsize=None)
def _b58_char_to_index_map() -> t.Mapping[int, int]:
    return {
        char: idx
        for idx, char in enumerate(B58_ALPHABET)
    }


def b58decode(data: bytes) -> bytes:
    """Decode data encoded as Base 58.

    Args:
        data: Data to decode.

    Returns:
        Original data.
    """
    scrubbed_data = data.lstrip(B58_ALPHABET[0:1])
    char_to_index = _b58_char_to_index_map()
    base = len(B58_ALPHABET)
    num = 0
    for char in scrubbed_data:
        num = num * base + char_to_index[char]

    number_of_leading_zeroes = len(data) - len(scrubbed_data)
    decoded = num.to_bytes(number_of_leading_zeroes + (num.bit_length() + 7) // 8, 'big')

    return decoded


def timestamp_to_aware_datetime(timestamp: t.Union[int, float]) -> datetime:
    """Convert a UNIX timestamp into an aware datetime in UTC.

    Args:
        timestamp: UNIX timestamp to convert.

    Returns:
        Converted timestamp into an aware datetime in UTC.
    """
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def file_mode_is_text(file: t.IO[t.AnyStr]) -> bool:
    """Check if a given file is opened in text mode, or otherwise in binary mode.

    Args:
        file: File to check its mode.

    Returns:
        True if file is opened in text mode, False otherwise.
    """
    return isinstance(file, io.TextIOBase)


def ordinal(number: int) -> str:
    """Convert an integer into its ordinal representation.

    Args:
        number: Integer number to get its ordinal representation.

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


def get_current_time() -> float:
    """Return the current time in seconds since the Epoch."""
    return time()


def generate_secret() -> str:
    """Generate a secure, pseudo-random value for use as a secret.

    Store the value generated by this function in your environment file, or secrets manager.

    Returns:
        A secure, pseudo-random value for use as a secret.
    """
    return b58encode(token_bytes(64)).decode()
