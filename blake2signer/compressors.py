"""Compressors: classes that implement the CompressorInterface."""

import gzip
import zlib

from .interfaces import CompressorInterface


class ZlibCompressor(CompressorInterface):
    """Zlib compressor."""

    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data using zlib.

        Args:
            data: Data to compress.
            level: Desired compression level.

        Returns:
            Raw compressed data.
        """
        return zlib.compress(data, level=level)

    def decompress(self, data: bytes) -> bytes:
        """Decompress given compressed data compressed with zlib.

        Args:
            data: Compressed data to decompress.

        Returns:
            Original data.
        """
        return zlib.decompress(data)


class GzipCompressor(CompressorInterface):
    """Gzip compressor."""

    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data using gzip.

        Args:
            data: Data to compress.
            level: Desired compression level.

        Returns:
            Raw compressed data.
        """
        return gzip.compress(data, compresslevel=level)

    def decompress(self, data: bytes) -> bytes:
        """Decompress given compressed data compressed with gzip.

        Args:
            data: Compressed data to decompress.

        Returns:
            Original data.
        """
        return gzip.decompress(data)
