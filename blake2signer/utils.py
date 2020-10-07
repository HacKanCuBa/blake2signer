"""Miscellaneous utilities."""

import base64
import typing


def force_bytes(value: typing.AnyStr) -> bytes:
    """Force a given value into bytes."""
    if isinstance(value, str):
        return value.encode('utf-8', errors='strict')

    return bytes(value)


def b64encode(data: typing.AnyStr) -> bytes:
    """Encode data as Base 64 URL safe, stripping padding."""
    return base64.urlsafe_b64encode(force_bytes(data)).rstrip(b'=')


def b64decode(data: typing.AnyStr) -> bytes:
    """Decode data encoded as Base 64 URL safe without padding."""
    data_b = force_bytes(data)

    return base64.urlsafe_b64decode(data_b + (b'=' * (len(data_b) % 4)))
