"""Fuzz the signers to search for vulnerabilities.

This module is intended to be run using `pythonfuzz`. See
https://gitlab.com/gitlab-org/security-products/analyzers/fuzzers/pythonfuzz

It has been optimized for CPython 3.11 due to extensive use of try/except blocks.

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
    python fuzz.py <signer> [fuzzer args...]

    where signer is one of:
        - blake2signer
        - blake2timestampsigner
        - blake2serializersigner

    and fuzzer args are pythonfuzz options.

Example:
    python fuzz.py blake2signer .fuzzed_blake2signer --runs 10000
"""

import importlib.util
import signal
import sys
from contextvars import ContextVar
from functools import partial
from functools import wraps
from io import BytesIO
from types import FrameType
from typing import Any
from typing import Callable
from typing import Dict
from typing import Optional
from typing import Type
from typing import TypeVar

from blake2signer import Blake2SerializerSigner
from blake2signer import Blake2Signer
from blake2signer import Blake2TimestampSigner
from blake2signer.bases import Blake2SignerBase
from blake2signer.errors import ConversionError
from blake2signer.errors import InvalidOptionError
from blake2signer.errors import MissingDependencyError
from blake2signer.errors import UnsignedDataError
from blake2signer.hashers import HasherChoice
from blake2signer.serializers import NullSerializer

SignedT = TypeVar('SignedT')
SignerT = TypeVar('SignerT', bound=Blake2SignerBase)

# Global signers collection to save on instantiation time
signers_ctx: ContextVar[Dict[str, Any]] = ContextVar(  # ToDo: properly type-hint this
    'signers_ctx',
    default={},
)


def kbinterrupt_handler(signum: int, _: Optional[FrameType]) -> None:
    """Handle keyboard interrupt (CTRL+C)."""
    print()
    print('Process interrupted!')
    sys.exit(128 + signum)


def get_signer(
    klass: Type[SignerT],
    *,
    hasher: HasherChoice,
    secret: bytes,
    **signer_kwargs: Any,
) -> SignerT:
    """Get a signer of the given class, for the given hasher.

    If the secret is improper for the class, then a generic one will be used, caching the
    class instantiation in a static variable for the duration of the script.

    Args:
        klass: Signer class.

    Keyword Args:
        hasher: A hasher from `HasherChoice`.
        secret: A secret.
        **signer_kwargs: Extra signer arguments.

    Returns:
        An instance of a signer.
    """
    try:
        return klass(secret, hasher=hasher, **signer_kwargs)
    except InvalidOptionError:
        # The secret is invalid, let's use a global signer cache to save on instantiation time
        signers = signers_ctx.get()
        signer_name = f'{klass.__name__}_{hasher.value}'

        try:
            signer = signers[signer_name]
        except KeyError:
            signer = klass(b's' * klass.MIN_SECRET_SIZE, hasher=hasher, **signer_kwargs)
            signers[signer_name] = signer
            signers_ctx.set(signers)

        return signer


def check_signing(
    data: bytes,
    *,
    sign: Callable[[bytes], SignedT],
    unsign: Callable[[SignedT], bytes],
) -> None:
    """Check signing data using given sign/unsign functions."""
    try:
        signed = sign(data)
    except UnsignedDataError:
        return

    unsigned = unsign(signed)
    if unsigned != data:
        raise ValueError(
            f'data mismatch: original:0x{data.hex()} != unsigned:0x{unsigned.hex()}',  # noqa: E231
        )


def import_pythonfuzz() -> Any:
    """Import PythonFuzz if possible, otherwise return a stub that will fail when used."""
    if importlib.util.find_spec('pythonfuzz') is None:

        class PythonFuzz:  # pylint: disable=R0903
            """Stub for PythonFuzz."""

            def __init__(self, _: Callable[[bytes], None]) -> None:
                """Stub for PythonFuzz."""
                raise MissingDependencyError(
                    'pythonfuzz can not be used if it is not installed: '
                    + 'python3 -m pip install --extra-index-url '
                    + 'https://gitlab.com/api/v4/projects/19904939/packages/pypi/simple '
                    + 'pythonfuzz',
                )

            def __call__(self, *_: Any, **__: Any) -> None:
                """Make this class callable."""

    else:
        from pythonfuzz.main import PythonFuzz  # type: ignore  # pylint: disable=C0415

    return PythonFuzz


def fuzz(func: Callable[[bytes], None]) -> Callable[[], None]:
    """Fuzz given function with pythonfuzzer.

    This decorator wraps PythonFuzz so that it can be safely used even if it is not installed.

    Returns:
        The decorated function.
    """

    @wraps(func)
    def inner() -> None:
        """Run pythonfuzzer."""
        pythonfuzz = import_pythonfuzz()

        pythonfuzz(func)()

    return inner


@fuzz
def fuzz_blake2signer(buf: bytes) -> None:  # pragma: nocover
    """Fuzz Blake2Signer to search for vulnerabilities.

    Raises:
        ValueError: unsigned data doesn't match original data.
    """
    hasher: HasherChoice  # PyCharm wrongly thinks that `hasher` is a string...
    for hasher in HasherChoice:
        signer: Blake2Signer = get_signer(Blake2Signer, hasher=hasher, secret=buf)

        # Check regular signing
        check_signing(buf, sign=signer.sign, unsign=signer.unsign)

        # Check signing in parts
        check_signing(buf, sign=signer.sign_parts, unsign=signer.unsign_parts)


@fuzz
def fuzz_blake2timestampsigner(buf: bytes) -> None:  # pragma: nocover
    """Fuzz Blake2TimestampSigner to search for vulnerabilities.

    Raises:
        ValueError: unsigned data doesn't match original data.
    """
    hasher: HasherChoice  # PyCharm wrongly thinks that `hasher` is a string...
    for hasher in HasherChoice:
        signer: Blake2TimestampSigner = get_signer(
            Blake2TimestampSigner,
            hasher=hasher,
            secret=buf,
        )

        # Check regular signing
        check_signing(buf, sign=signer.sign, unsign=partial(signer.unsign, max_age=None))

        # Check signing in parts
        check_signing(
            buf,
            sign=signer.sign_parts,
            unsign=partial(signer.unsign_parts, max_age=None),
        )


@fuzz
def fuzz_blake2serializersigner(buf: bytes) -> None:  # noqa: C901  # pragma: nocover
    """Fuzz Blake2SerializerSigner to search for vulnerabilities.

    Raises:
        ValueError: unsigned data doesn't match original data.
    """
    hasher: HasherChoice  # PyCharm wrongly thinks that `hasher` is a string...
    for hasher in HasherChoice:
        signer: Blake2SerializerSigner = get_signer(
            Blake2SerializerSigner,
            hasher=hasher,
            secret=buf,
            serializer=NullSerializer,
        )

        # Check regular signing
        check_signing(buf, sign=signer.dumps, unsign=signer.loads)

        # Check signing in parts
        check_signing(buf, sign=signer.dumps_parts, unsign=signer.loads_parts)

        # Check signing using a file
        def dump(data: bytes) -> BytesIO:
            """Serialize and sign data to a file."""
            file = BytesIO()
            try:  # pylint: disable=R8203  # try/except blocks are fine for CPython >= 3.11
                signer.dump(data, file)  # noqa: B023  # pylint: disable=W0640  # usage on purpose
            except ConversionError as exc:  # This should be impossible, so let's check it
                raise ValueError(
                    f'impossible ConversionError achieved with 0x{data.hex()}',
                ) from exc

            return file

        def load(file: BytesIO) -> bytes:
            """Recover original data from a signed serialized file from `dump`."""
            file.seek(0)
            return signer.load(file)  # noqa: B023  # pylint: disable=W0640  # usage on purpose

        check_signing(buf, sign=dump, unsign=load)


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


signal.signal(signal.SIGINT, kbinterrupt_handler)

if __name__ == '__main__':  # pragma: nocover
    main()
