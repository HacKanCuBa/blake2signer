"""BLAKE3 module to handle the optional `blake3` package.

When, and if, this package gets to the Python core, we can remove this.
"""

import importlib.util
import typing

from blake2signer.errors import MissingDependencyError

if importlib.util.find_spec('blake3') is None:

    def blake3(*_: typing.Any, **__: typing.Any) -> typing.Any:
        """BLAKE3 function stub."""
        raise MissingDependencyError(
            'blake3 can not be selected if it is not installed: python3 -m pip install blake3',
        )

    _HAS_BLAKE3 = False
else:
    from blake3 import blake3  # noqa: F401  # pylint: disable=W0611

    _HAS_BLAKE3 = True


def has_blake3() -> bool:
    """Return True if the `blake3` package is installed."""
    return _HAS_BLAKE3
