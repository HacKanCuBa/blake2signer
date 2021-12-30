"""Compressors: classes that implement the CompressorInterface."""

import gzip
import zlib

from .interfaces import CompressorInterface


class ZlibCompressor(CompressorInterface):
    """Zlib compressor."""

    @property
    def default_compression_level(self) -> int:
        """Get the default compression level."""
        return zlib.Z_DEFAULT_COMPRESSION

    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data using zlib.

        Args:
            data: Data to compress.

        Keyword Args:
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

    @property
    def default_compression_level(self) -> int:
        """Get the default compression level."""
        return 9  # According to https://docs.python.org/3/library/gzip.html

    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data using gzip.

        Args:
            data: Data to compress.

        Keyword Args:
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
