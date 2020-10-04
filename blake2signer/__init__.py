# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# by HacKan (https://hackan.net), 2020.
# This software is provided as-is. You are free to use, share, modify
# and share modifications under the terms of that license, even with
# proprietary code. Attribution is not required to share but is
# appreciated.
"""Blake2Signer: use Blake2 in keyed hashing mode to sign and verify data.

The goal of this module is to provide a simple way to securely sign data and the
main use case is to sign cookies. There are much better packages for other or
more general use cases. This module uses Blake2 in keyed hashing mode. For more
information regarding this see:
https://docs.python.org/3/library/hashlib.html#blake2

This module provides three classes:

- Blake2Serializer: a high-level signer class that handles data serialization,
  compression and encoding along with signing and timestamped signing.
- Blake2Signer: a low-level signer class that simply signs and verifies data as
  bytes.
- Blake2TimestampSigner: a low-level signer class that simply signs and verifies
  timestamped data as bytes.

You can't mix and match signers, and that's or purpose: if you need anything more
complex consider using "itsdangerous", Django's signer, "pypaseto", "pyjwt" or
others like those.
This means that unsigning a stream signed by Blake2Signer using
Blake2TimestampSigner may result in corrupt data and/or an error checking the
timestamp (considering that the key is the same for both), and the same goes for
the other way around.
When using Blake2Serializer you need to know the settings to sign/unsign from
beforehand: again, those are not stored in the stream. I.e.: signing some
compressed data but unsigning without compression may result in a DecodeError
exception or in invalid data.

by HacKan (https://hackan.net), 2020.
Ref: https://gitlab.com/hackancuba/blake2signer

If you think on something else, have questions, concerns or great ideas please
feel free to contact me. If you use this code in your app I would greatly appreciate
a "thumbs up" and to share your use case and implementation :)

See examples in the README.
"""

from . import errors
from .serializers import Blake2Serializer
from .signers import Blake2Signer
from .signers import Blake2TimestampSigner

__version__ = '0.3.0'

__all__ = (
    'errors',
    'Blake2Serializer',
    'Blake2Signer',
    'Blake2TimestampSigner',
)
