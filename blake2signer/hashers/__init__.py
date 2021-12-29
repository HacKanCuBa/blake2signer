"""Hashers handlers.

These are not meant to be used directly, but otherwise through a signer.
"""
import typing

from .blake3_package import blake3
from .blake3_package import has_blake3
from .blakehashers import BLAKE2Hasher
from .blakehashers import BLAKE3Hasher
from .blakehashers import HasherChoice

BLAKEHasher = typing.Union[BLAKE2Hasher, BLAKE3Hasher]

__all__ = (
    'blake3',  # Always import blake3 from this module
    'BLAKEHasher',
    'BLAKE2Hasher',
    'BLAKE3Hasher',
    'has_blake3',
    'HasherChoice',
)
