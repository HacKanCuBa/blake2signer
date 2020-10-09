"""Errors."""


class SignerError(Exception):
    """Base exception for all errors."""


class InvalidOptionError(SignerError):
    """Invalid option error.

    Means that given value is out of bounds or has the wrong format or type for
    the option.
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
    safely catch it to deal with signed data errors (produced during `unsgin` or
    `loads`).
    """


class UnsignedDataError(DataError):
    """Unsigned data error.

    Generic data error that occurred for data to be signed that is being processed.

    All exceptions regarding non-signed data handling depends on this one, so you
    can safely catch it to deal with non-signed data errors (produced during
    `sign` or `dumps`).
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

    Means that given data could not be decoded from base64 URL safe.
    """


class EncodeError(UnsignedDataError):
    """Encode error.

    Means that given data could not be encoded to base64 URL safe.
    """


class ConversionError(SignedDataError, UnsignedDataError):
    """Conversion error.

    Means that given data could not be converted to bytes. This can happen during
    either `sign`/`dumps` and `unsign`/`loads`.
    """
