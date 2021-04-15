"""Miscellaneous utilities."""

import base64
import typing


def force_bytes(value: typing.Any) -> bytes:
    """Force a given value into bytes."""
    if isinstance(value, bytes):
        return value
    elif isinstance(value, str):
        return value.encode('utf-8', errors='strict')

    return bytes(value)


def b64encode(data: bytes) -> bytes:
    """Encode data as Base 64 URL safe, stripping padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def b64decode(data: bytes) -> bytes:
    """Decode data encoded as Base 64 URL safe without padding."""
    return base64.urlsafe_b64decode(data + (b'=' * (len(data) % 4)))


def b32encode(data: bytes) -> bytes:
    """Encode data as Base 32, stripping padding."""
    return base64.b32encode(data).rstrip(b'=')


def b32decode(data: bytes) -> bytes:
    """Decode data encoded as Base 32 without padding."""
    return base64.b32decode(data + (b'=' * ((8 - (len(data) % 8)) % 8)))
