"""Compressors: classes that implement the CompressorInterface."""

import gzip
import zlib

from .interfaces import CompressorInterface


class ZlibCompressor(CompressorInterface):
    """Zlib compressor."""

    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data using zlib."""
        return zlib.compress(data, level=level)

    def decompress(self, data: bytes) -> bytes:
        """Decompress given compressed data compressed with zlib."""
        return zlib.decompress(data)


class GzipCompressor(CompressorInterface):
    """Gzip compressor."""

    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data using gzip."""
        return gzip.compress(data, compresslevel=level)

    def decompress(self, data: bytes) -> bytes:
        """Decompress given compressed data compressed with gzip."""
        return gzip.decompress(data)
