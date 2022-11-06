"""Fuzz the signers to search for vulnerabilities.

This module is intended to be run using `pythonfuzz`. See
https://gitlab.com/gitlab-org/security-products/analyzers/fuzzers/pythonfuzz

Note:
    Install `pythonfuzz` via:
        pip install \
            --extra-index-url https://gitlab.com/api/v4/projects/19904939/packages/pypi/simple \
            pythonfuzz
    Or:
        poetry source add --secondary \
            pythonfuzz \
            https://gitlab.com/api/v4/projects/19904939/packages/pypi/simple
        poetry add --group dev --source pythonfuzz pythonfuzz

Usage:
    python fuzz.py (signer) [options]

    where signer is one of:
        - blake2signer
        - blake2timestampsigner
        - blake2serializersigner

    and options are pythonfuzz options.

Example:
    python fuzz.py blake2signer .fuzzed_blake2signer --runs 10000
"""

import signal
import sys
from io import BytesIO
from types import FrameType
from typing import Optional

from pythonfuzz.main import PythonFuzz

from blake2signer import Blake2SerializerSigner
from blake2signer import Blake2Signer
from blake2signer import Blake2TimestampSigner
from blake2signer import errors
from blake2signer.serializers import NullSerializer

SECRET = b's' * Blake2Signer.MIN_SECRET_SIZE
# Make them global so there's only one instantiation, making the fuzzing faster
b_signer = Blake2Signer(SECRET)
t_signer = Blake2TimestampSigner(SECRET)
s_signer = Blake2SerializerSigner(
    SECRET,
    serializer=NullSerializer,  # JSON can't handle bytes
)


def kbinterrupt_handler(signum: int, _: Optional[FrameType]) -> None:
    """Handle keyboard interrupt (CTRL+C)."""
    print()
    print('Process interrupted!')
    sys.exit(128 + signum)


signal.signal(signal.SIGINT, kbinterrupt_handler)


@PythonFuzz  # type: ignore
def fuzz_blake2signer(buf: bytes) -> None:  # noqa: C901 R701
    """Fuzz Blake2Signer to search for vulnerabilities.

    Raises:
        ValueError: unsigned data doesn't match original data.
    """
    try:
        signer = Blake2Signer(buf)
    except errors.InvalidOptionError:
        signer = b_signer

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
        raise ValueError(f'data mismatch: unsigned:0x{unsigned.hex()} != original:0x{buf.hex()}')

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
        raise ValueError(f'data mismatch: unsigned:0x{unsigned.hex()} != original:0x{buf.hex()}')


@PythonFuzz  # type: ignore
def fuzz_blake2timestampsigner(buf: bytes) -> None:  # noqa: C901 R701
    """Fuzz Blake2TimestampSigner to search for vulnerabilities.

    Raises:
        ValueError: unsigned data doesn't match original data.
    """
    try:
        signer = Blake2TimestampSigner(buf)
    except errors.InvalidOptionError:
        signer = t_signer

    # Check regular signing
    try:
        signed = signer.sign(buf)
    except errors.UnsignedDataError:
        return

    try:
        unsigned = signer.unsign(signed, max_age=10)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:0x{unsigned.hex()} != original:0x{buf.hex()}')

    # Check signing in parts
    try:
        signature = signer.sign_parts(buf)
    except errors.UnsignedDataError:
        return

    try:
        unsigned = signer.unsign_parts(signature, max_age=10)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:0x{unsigned.hex()} != original:0x{buf.hex()}')


@PythonFuzz  # type: ignore
def fuzz_blake2serializersigner(buf: bytes) -> None:  # noqa: C901 R701
    """Fuzz Blake2SerializerSigner to search for vulnerabilities.

    Raises:
        ValueError: unsigned data doesn't match original data.
    """
    try:
        signer = Blake2SerializerSigner(buf, serializer=NullSerializer)
    except errors.InvalidOptionError:
        signer = s_signer

    # Check regular signing
    try:
        signed = signer.dumps(buf)
    except errors.UnsignedDataError:
        return

    try:
        unsigned = signer.loads(signed)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:0x{unsigned.hex()} != original:0x{buf.hex()}')

    # Check signing in parts
    try:
        signature = signer.dumps_parts(buf)
    except errors.UnsignedDataError:
        return

    try:
        unsigned = signer.loads_parts(signature)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:0x{unsigned.hex()} != original:0x{buf.hex()}')

    # Check signing using a file
    file = BytesIO()
    try:
        signer.dump(buf, file)
    except errors.ConversionError as exc:  # This should be impossible, so let's check it
        raise ValueError(f'impossible error achieved with 0x{buf.hex()}') from exc
    except errors.UnsignedDataError:
        return

    file.seek(0)
    try:
        unsigned = signer.load(file)
    except errors.SignedDataError:
        return

    if unsigned != buf:
        raise ValueError(f'data mismatch: unsigned:0x{unsigned.hex()} != original:0x{buf.hex()}')


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
