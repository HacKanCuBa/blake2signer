"""Compressors: classes that implement the CompressorInterface."""

import zlib

from .interfaces import CompressorInterface


class ZlibCompressor(CompressorInterface):
    """Compressor."""

    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data."""
        return zlib.compress(data, level=level)

    def decompress(self, data: bytes) -> bytes:
        """Decompress given compressed data."""
        return zlib.decompress(data)
