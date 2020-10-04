"""Miscellaneous utilities."""

import base64
import typing


def b64encode(data: bytes) -> bytes:
    """Encode data as Base 64 URL safe, stripping padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def b64decode(data: typing.Union[bytes, str]) -> bytes:
    """Decode data encoded as Base 64 URL safe without padding."""
    if isinstance(data, str):
        data = data.encode()

    return base64.urlsafe_b64decode(data + b'=' * (len(data) % 4))


def force_bytes(value: typing.AnyStr) -> bytes:
    """Force a given value into bytes."""
    if isinstance(value, str):
        return value.encode('utf-8', errors='strict')

    return bytes(value)
