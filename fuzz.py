"""Fuzz the signers to search for vulnerabilities.

This module is intended to be run using `pythonfuzz`. See
https://gitlab.com/gitlab-org/security-products/analyzers/fuzzers/pythonfuzz
"""

import sys
from io import BytesIO

from pythonfuzz.main import PythonFuzz

from blake2signer import Blake2SerializerSigner
from blake2signer import Blake2Signer
from blake2signer import Blake2TimestampSigner
from blake2signer import errors
from blake2signer.serializers import NullSerializer

secret = b's' * Blake2Signer.MIN_SECRET_SIZE
# Make them global so there's only one instantiation, making the fuzzing faster
signer = Blake2Signer(secret)
t_signer = Blake2TimestampSigner(secret)
s_signer = Blake2SerializerSigner(
    secret,
    serializer=NullSerializer,  # JSON can't handle bytes
)


@PythonFuzz
def fuzz_blake2signer(buf: bytes):  # noqa: C901 R701
    """Fuzz Blake2Signer to search for vulnerabilities.

    Raises:
        ValueError: unsigned data doesn't match original data.
    """
    # Check regular signing
    try:
        signed = signer.sign(buf)
    except errors.UnsignedDataError:
        return

    try:
        unsigned = signer.unsign(signed)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:{unsigned} != original:{buf}')

    # Check signing in parts
    try:
        signature = signer.sign_parts(buf)
    except errors.UnsignedDataError:
        return

    try:
        unsigned = signer.unsign_parts(signature)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:{unsigned} != original:{buf}')


@PythonFuzz
def fuzz_blake2timestampsigner(buf: bytes) -> None:  # noqa: C901 R701
    """Fuzz Blake2TimestampSigner to search for vulnerabilities.

    Raises:
        ValueError: unsigned data doesn't match original data.
    """
    # Check regular signing
    try:
        signed = t_signer.sign(buf)
    except errors.UnsignedDataError:
        return

    try:
        unsigned = t_signer.unsign(signed, max_age=10)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:{unsigned} != original:{buf}')

    # Check signing in parts
    try:
        signature = t_signer.sign_parts(buf)
    except errors.UnsignedDataError:
        return

    try:
        unsigned = t_signer.unsign_parts(signature, max_age=10)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:{unsigned} != original:{buf}')


@PythonFuzz
def fuzz_blake2serializersigner(buf: bytes) -> None:  # noqa: C901 R701
    """Fuzz Blake2SerializerSigner to search for vulnerabilities.

    Raises:
        ValueError: unsigned data doesn't match original data.
    """
    # Check regular signing
    try:
        signed = s_signer.dumps(buf)
    except errors.UnsignedDataError:
        return

    try:
        unsigned = s_signer.loads(signed)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:{unsigned} != original:{buf}')

    # Check signing in parts
    try:
        signature = s_signer.dumps_parts(buf)
    except errors.UnsignedDataError:
        return

    try:
        unsigned = s_signer.loads_parts(signature)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:{unsigned} != original:{buf}')

    # Check signing using a file
    file = BytesIO()
    try:
        s_signer.dump(buf, file)
    except errors.ConversionError:
        raise  # This should be impossible, so let's check it
    except errors.UnsignedDataError:
        return

    file.seek(0)
    try:
        unsigned = s_signer.load(file)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:{unsigned} != original:{buf}')


def main() -> None:
    """Run fuzzing according to user arguments."""
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <signer> [fuzzer args...]')
        print('Where signer is one of the signers provided by this package')
        sys.exit(1)

    wanted_signer = sys.argv.pop(1)  # Remove argument, so the fuzzer doesn't get it
    func_name = f'fuzz_{wanted_signer.lower()}'
    if func_name not in globals():
        print(
            'Signer does not exist or can not be fuzzed: fuzzer not implemented for',
            wanted_signer,
        )
        sys.exit(1)

    fuzzer = globals()[func_name]
    print('Fuzzing for', wanted_signer, '...')
    fuzzer()


if __name__ == '__main__':
    main()
