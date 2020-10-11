# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# by HacKan (https://hackan.net), 2020.
# This software is provided as-is. You are free to use, share, modify
# and share modifications under the terms of that license, even with
# proprietary code. Attribution is not required to share but is
# appreciated.
"""Blake2Signer: use Blake2 in keyed hashing mode to sign and verify signed data.

The goal of this module is to provide a simple way to securely sign data and the
main use case is to sign cookies, using Blake2 in keyed hashing mode (read more
about that in https://docs.python.org/3/library/hashlib.html#blake2). There are
much better packages for other or more general use cases, such as itsdangerous,
Django's Signer, pypaseto, pyjwt, etc. Refer to them if you find this module
lacking features and/or create an issue in the repo to request for it.

Canonical repository: https://gitlab.com/hackancuba/blake2signer

If you think on something else, have questions, concerns or great ideas please
feel free to contact me. If you use this code in your app I would greatly appreciate
a "thumbs up" and to share your use case and implementation :)

See examples and more info in the README.
"""

from . import errors
from .serializers import Blake2SerializerSigner
from .signers import Blake2Signer
from .signers import Blake2TimestampSigner

__version__ = '0.4.0'

__all__ = (
    'errors',
    'Blake2SerializerSigner',
    'Blake2Signer',
    'Blake2TimestampSigner',
)
