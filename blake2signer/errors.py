"""Errors: contains all errors and exceptions raised by this lib.

Note:
    Here's the hierarchy tree:

        SignerError
            |
            |-- InvalidOptionError: given option value is out of bounds, has the wrong
            |                       format or type.
            |
            |-- MissingDependencyError: a required dependency is not installed.
            |
            |
            |-- DataError: generic data error.
                    |
                    |-- SignedDataError: error that occurred for *signed data*.
                    |       |
                    |       |-- SignatureError: error encountered while dealing with
                    |       |       |           the signature.
                    |       |       |
                    |       |       |-- InvalidSignatureError: the signature is not
                    |       |               |                  valid.
                    |       |               |
                    |       |               |-- ExpiredSignatureError: the signature
                    |       |                                          has expired.
                    |       |
                    |       |-- UnserializationError: given data could not be
                    |       |                         unserialized.
                    |       |
                    |       |-- DecompressionError: given data could not be decompressed.
                    |       |
                    |       |-- DecodeError: given data could not be decoded.
                    |       |
                    |       |-- ConversionError: given data could not be converted
                    |       |                    to bytes.
                    |       |
                    |       |-- FileError: error while reading the file.
                    |
                    |-- UnsignedDataError: error that occurred for *data to be signed*.
                            |
                            |-- SerializationError: given data could not be serialized.
                            |
                            |-- CompressionError: given data could not be compressed.
                            |
                            |-- EncodeError: given data could not be encoded.
                            |
                            |-- ConversionError: given data could not be converted
                            |                    to bytes.
                            |
                            |-- FileError: error while writing the file.
"""

import typing
from datetime import datetime


class SignerError(Exception):
    """Base exception for all errors."""


class InvalidOptionError(SignerError):
    """Invalid option error.

    Means that given value is out of bounds or has the wrong format or type for
    the option.
    """


class MissingDependencyError(SignerError):
    """Missing dependency error.

    Means that a required dependency is not installed.
    """


class DataError(SignerError):
    """Data error.

    Generic data error meaning that given data could not be processed correctly.

    All exceptions regarding data handling depends on this one, so you can safely
    catch it to deal with data errors (both signed and to be signed).
    """


class SignedDataError(DataError):
    """Signed data error.

    Generic data error that occurred for signed data that is being processed.

    All exceptions regarding signed data handling depends on this one, so you can
    safely catch it to deal with signed data errors (produced during `unsign`,
    `unsign_parts`, `loads`, `loads_parts`, or `load`).
    """


class UnsignedDataError(DataError):
    """Unsigned data error.

    Generic data error that occurred for data to be signed that is being processed.

    All exceptions regarding non-signed data handling depends on this one, so you
    can safely catch it to deal with non-signed data errors (produced during
    `sign`, `sign_parts`, `dumps`, `dumps_parts` or `dump`).
    """


class SignatureError(SignedDataError):
    """Signature error.

    Means that an error was encountered while dealing with some part of the
    signature.
    """


class InvalidSignatureError(SignatureError):
    """Invalid signature error.

    Means that the signature is not valid.
    """


class ExpiredSignatureError(InvalidSignatureError):
    """Expired signature error.

    Means that the signature has expired.
    """

    # ToDo: D417 is a false positive, see https://github.com/PyCQA/pydocstyle/issues/514
    def __init__(self, *args: typing.Any, timestamp: datetime) -> None:  # noqa: D417
        """Initialize self.

        Args:
            *args: Additional positional arguments, see `Exception.__init__`.

        Keyword Args:
            timestamp: An aware datetime object indicating when the signature was done.
        """
        super().__init__(*args)

        self.timestamp: datetime = timestamp


class UnserializationError(SignedDataError):
    """Unserialization error.

    Means that given data could not be unserialized.
    """


class SerializationError(UnsignedDataError):
    """Serialization error.

    Means that given data could not be serialized.
    """


class DecompressionError(SignedDataError):
    """Decompression error.

    Means that given data could not be decompressed.
    """


class CompressionError(UnsignedDataError):
    """Compression error.

    Means that given data could not be compressed.
    """


class DecodeError(SignedDataError):
    """Decode error.

    Means that given data could not be decoded.
    """


class EncodeError(UnsignedDataError):
    """Encode error.

    Means that given data could not be encoded.
    """


class ConversionError(SignedDataError, UnsignedDataError):
    """Conversion error.

    Means that given data could not be converted to bytes. This can happen for
    any process.
    """


class FileError(SignedDataError, UnsignedDataError):
    """File error.

    Means that an operation pertaining a file failed. This can happen during
    `dump` or `load`.
    """
