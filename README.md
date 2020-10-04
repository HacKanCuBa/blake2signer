# Blake2Signer

The goal of this module is to provide a simple way to securely sign data using Blake2 in keyed hashing mode (read more about that in the [hashlib docs](https://docs.python.org/3/library/hashlib.html#blake2)).
 
 The main use case is to sign cookies or similar data. There are much better packages for other use cases or more general use cases so if you feel this module doesn't satisfy your needs consider using "itsdangerous", Django's signer, "pypaseto", "pyjwt" or others like those. My idea is to keep this module as simple as possible without much room to become a *footgun*.

This project began initially as a Gist but I decided to create a package because I think it can be useful as a small (~500 LoC), simple (quite straightforward) and fast data signer (see more below).

## Goals

* Be simple and straightforward.
* Follow [semver](https://semver.org/).
* Be always typed.
* No dependencies (besides dev).
* 100% coverage.

### Secondary goals

* If possible, maintain current active Python versions (3.7+).

## Requirements

* Python 3.7+

## Usage

This module provides three classes:

* `Blake2Serializer`: a high-level signer class that handles data serialization, compression and encoding along with signing and timestamped signing.
* `Blake2Signer`: a low-level signer class that simply salts, signs and verifies data as bytes.
* `Blake2TimestampSigner`: a low-level signer class that simply salts, signs and verifies timestamped data as bytes.

You can't mix and match signers, and that's on purpose. This means that unsigning a stream signed by Blake2Signer using
Blake2TimestampSigner may result in corrupt data and/or an error checking the timestamp (considering that the key and person is the same for both), and the same goes for the other way around.

You should generally go for the high-level signer class.

In all classes you can choose between blake2b (default) or blake2s as hasher and change the digest size with a secure minimum enforced (defaults to the maximum size for the hasher in the low-level classes and to 16 bytes for the high-level ones). The secret/key is enforced to be of a secure minimum size, where high-level classes have no size limit but low-level ones do (depending on the hasher).

### Examples

The following examples are working code and should run as-is.

#### Tl; Dr

```python
"""Tl;dr example."""

from datetime import timedelta

from blake2signer import Blake2Serializer

secret = b'secure-secret-that-nobody-knows!'
# some arbitrary data to sign
data = {'message': 'attack at dawn', 'extra': [1, 2, 3, 4]}

# Define same signer to `dumps` and `loads`.
signer = Blake2Serializer(
    secret,
    max_age=timedelta(days=1),
    person=b'message-cookie-signer',
)

# Sign and i.e. store the data in a cookie
signed = signer.dumps(data, use_compression=True)
cookie = {'data': signed}

# To verify simply use loads: you will either get the data or a
# `SignerError` subclass exception.
unsigned = signer.loads(cookie.get('data', ''))
print(unsigned['message'], unsigned['extra'])  # attack at dawn [1, 2, 3, 4]
```

#### High level classes

This is probably what you want to use :)

Both the *secret* and *personalisation* parameters are derived so they have no length limit. Input data can always be arbitrarily long.

As a general rule of thumb if you have highly compressible data such as human readable text, then you should enable compression. Otherwise when dealing with somewhat random data compression won't help much (but probably won't hurt either unless you're dealing with a huge amount of data).

Whenever possible set a *personalisation string* which can be any arbitrarily long string. For example if you use a signer for cookies set something like `b'cookies-signer'` or if you use it for some user-related data signing it could be `b'user-data-signer'`. This personalisation string helps defeating the abuse of a signed stream for different signers that share the same key. See an example of this below and read more about it in the [hashlib docs](https://docs.python.org/3/library/hashlib.html#personalization).

```python
"""Usage examples."""

from datetime import timedelta

from blake2signer import Blake2Serializer
from blake2signer import errors

# Simple data serialization and signing
secret = b'ZnVja3RoZXBvbGljZQ'
data = [{'a': 'b'}, 1] * 10000  # some big data structure
print(len(data))  # 20000

signer = Blake2Serializer(secret)  # without timestamp nor compression
signed = signer.dumps(data)
print(len(signed))  # 160044

unsigned = signer.loads(signed)
print(data == unsigned)  # True

signer = Blake2Serializer(  # with timestamp
    secret,
    max_age=timedelta(weeks=1),
)
signed = signer.dumps(data, use_compression=True)  # with compression
print(len(signed))  # 412  # compression helped reducing size heavily

unsigned = signer.loads(signed)
print(data == unsigned)  # True

signer = Blake2Serializer(  # with timestamp and personalisation
    secret,
    max_age=timedelta(weeks=1),
    person=b'my-cookie-signer',
)
try:
    signer.loads(signed)
except errors.InvalidSignatureError as exc:
    print(exc)  # signature is not valid
# Using the `person` parameter made the sig to fail, thus protecting signed
# data to be loaded incorrectly.

signed = signer.dumps(data, use_compression=True)  # with compression
print(len(signed))  # 412  # compression helped reducing size heavily

unsigned = signer.loads(signed)
print(data == unsigned)  # True
```

#### Low level classes

You probably don't want to use these ones unless you are quite sure you do.

Note that *key* and *personalisation* parameters are NOT derived and are used as-is, so algorithm size limits apply. Input data can always be arbitrarily long.

```python
"""Usage examples."""

from blake2signer import Blake2Signer
from blake2signer import Blake2TimestampSigner


# Low level data signing (for bytes data only)
key = b'ZnVja3RoZXBvbGljZQ'
data = b'facundo castro presente'

signer = Blake2Signer(key)  # without timestamp
signed = signer.sign(data)
print(len(signed))  # 103

unsigned = signer.unsign(signed)
print(data == unsigned)  # True

signer = Blake2TimestampSigner(key)  # with timestamp
signed = signer.sign(data)
print(len(signed))  # 107

unsigned = signer.unsign(signed, max_age=10)
print(data == unsigned)  # True

# Using Blake2s instead of Blake2b
signer = Blake2Signer(key, hasher=Blake2Signer.Hashers.blake2s)
signed = signer.sign(data)
print(len(signed))  # 63

unsigned = signer.unsign(signed)
print(data == unsigned)  # True
```

#### Wrong usage examples

This section is meant to describe how signers can be misused so you can avoid the mistakes described here.

```python
"""Wrong usage examples."""

from blake2signer import Blake2Signer
from blake2signer import Blake2TimestampSigner
from blake2signer.errors import ExpiredSignatureError
from blake2signer.errors import InvalidSignatureError

# Let's mix and match, what could go wrong? spoiler: everything!
key = b'ZnVja3RoZXBvbGljZQ'
data = b'#ACAB'

signer = Blake2Signer(key)
t_signer = Blake2TimestampSigner(key)

try:
    t_signer.unsign(signer.sign(data), max_age=1)
except ExpiredSignatureError as exc:
    print(repr(exc))
# We see an exception because since the signature is OK the timestamped signer
# is considering the 4 bytes `b'ACAB'` as a timestamp which gives us
# 2004-09-11T15:17:38, way in the past. Is this an issue with the signer? NO.
# As stated before, one must be careful of NOT mixing and matching things.

signer.unsign(t_signer.sign(data))  # b'...#ACAB'
# This time we don't even get an exception because all is OK for the signer,
# but the recovered data is wrong! It contains the timestamp from the timestamp
# signer.

# When using different signers for different things, its a good idea to use
# the personalisation parameter which prevents these situations:
signer = Blake2Signer(key, person=b'1234')
signer.unsign(signer.sign(data))  # b'#ACAB'

try:
    signer.unsign(t_signer.sign(data))
except InvalidSignatureError as exc:
    print(repr(exc))
# Even though the key/secret is the same, the personalisation parameter changes
# the hashing output thus changing the signature. This is very useful to
# prevent these situations and should be implemented whenever used. It doesn't
# have to be random nor secret nor too long, it just needs to be unique for
# the usage. There's a limit to its size in the low level classes but the high
# level classes derives the value so it has no practical limit.
```

The moral of the story is: always sign and unsign using the exact same signer with the exact same parameters (there aren't many anyway), and use the personalisation parameter whenever you can.

#### Real use case example

Sign cookies in a FastAPI/Starlette middleware.

```python
"""Sample use case: sign cookies in a FastAPI/Starlette middleware."""

from datetime import timedelta

from fastapi import Request
from fastapi import Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.base import RequestResponseEndpoint

from blake2signer import Blake2Serializer
from blake2signer.errors import DecodeError

# from .messages import Messages  # Some class that has the data we want to sign
class Messages:
    
    def to_dict(self) -> dict:
        pass

    @classmethod
    def from_dict(cls, data: dict) -> 'Messages':
        pass

# In this example, that class can be converted to/read from dict.
# It doesn't need to be exactly a dict but any Python type that
# can be JSON encodable. Since Python classes are already dicts
# (unless they use `__slots__`), this is the most convenient portable
# way. DO NOT USE PICKLE!! ITS UNSAFE AND LEADS TO CODE EXECUTION!

SECRET_KEY: bytes = 'myverysecretsecret'.encode()
COOKIE_TTL: timedelta = timedelta(days=5)
COOKIE_NAME: str = 'my_cookie'


class CookieHTTPMiddleware(BaseHTTPMiddleware):

    @property
    def _signer(self) -> Blake2Serializer:
        return Blake2Serializer(
            SECRET_KEY,
            max_age=COOKIE_TTL,
            person=b'cookie_http_middleware',
        )
    
    def get_cookie_data(self, request: Request) -> Messages:
        signed_data = request.cookies.get(COOKIE_NAME, '')
        messages_data = self._signer.loads(signed_data)  # may raise DecodeError
        messages = Messages.from_dict(messages_data)
        return messages

    def set_cookie_data(self, messages: Messages, response: Response) -> None:
        data = messages.to_dict()
        signed_data = self._signer.dumps(data, use_compression=True)
        response.set_cookie(
            COOKIE_NAME,
            value=signed_data,
            max_age=int(COOKIE_TTL.total_seconds()),
            secure=True,
            httponly=True,
            samesite='strict',
        )

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        try:
            request.state.messages = self.get_cookie_data(request)
        except DecodeError:  # some tampering, maybe we changed the secret...
            request.state.messages = Messages()

        response = await call_next(request)

        # You may want to implement some change detection mechanism to avoid
        # writing cookies in every response.
        # if changed(request.state.messages):
        self.set_cookie_data(request.state.messages, response)

        return response
```

## Comparison with other libs

It's easy to compare this lib to, say, [itsdangerous](https://itsdangerous.palletsprojects.com/en/1.1.x) and [django](https://www.djangoproject.com).
 
 Regarding **itsdangerous** (1.1.0), I found this lib to be *marginally faster* (~3%) when compared to it using blake2b or blake2s, *quite faster* regarding sha256 (~55%), 384 (~15%) and 512 (~15%) and *slower* regarding sha1 (~15%) (this is most likely due to CPU instructions optimization).

 Regarding **django** (3.1.2), I found this lib to be *quite faster* (~17%) when compared to it using blake2b or blake2s, *incredibly faster* regarding sha256 (~92%), 384 (~55%) and 512 (~55%) and *marginally faster* regarding sha1 (~4%). I have no idea what's going on with Django! It seems its doing too many additional operations. Additionally its Signer doesn't handle arbitrary bytes well (it breaks raising `BadSignature` if you use `datab` below, so it needs `datas`).

```python
"""Timing comparison."""

import json
from hashlib import blake2b
from hashlib import sha1
from hashlib import sha256
from hashlib import sha384
from hashlib import sha512

from django.core import signing
from itsdangerous import Signer
from itsdangerous import URLSafeSerializer

from blake2signer import Blake2Serializer
from blake2signer import Blake2Signer

secret = b'1' * 16
data = [{'a': 'b'}, 1] * 100000  # some big data structure
datas = json.dumps(data)
datab = datas.encode()

b2s = Blake2Signer(secret)
id_b2 = Signer(secret, digest_method=blake2b)
id_s1 = Signer(secret, digest_method=sha1)
id_s256 = Signer(secret, digest_method=sha256)
id_s384 = Signer(secret, digest_method=sha384)
id_s512 = Signer(secret, digest_method=sha512)
djs_b2 = signing.Signer(secret, algorithm='blake2b')
djs_s1 = signing.Signer(secret, algorithm='sha1')
djs_s256 = signing.Signer(secret, algorithm='sha256')
djs_s384 = signing.Signer(secret, algorithm='sha384')
djs_s512 = signing.Signer(secret, algorithm='sha512')

# Using ipython:
%timeit b2s.unsign(b2s.sign(datab))
%timeit id_b2.unsign(id_b2.sign(datab))
%timeit id_s1.unsign(id_s1.sign(datab))
%timeit id_s256.unsign(id_s256.sign(datab))
%timeit id_s384.unsign(id_s384.sign(datab))
%timeit id_s512.unsign(id_s512.sign(datab))
%timeit djs_b2.unsign(djs_b2.sign(datas))
%timeit djs_s1.unsign(djs_s1.sign(datas))
%timeit djs_s256.unsign(djs_s256.sign(datas))
%timeit djs_s384.unsign(djs_s384.sign(datas))
%timeit djs_s512.unsign(djs_s512.sign(datas))

b2ss = Blake2Serializer(secret)
id_b2s = URLSafeSerializer(secret, signer_kwargs={'digest_method': blake2b})

%timeit b2ss.loads(b2ss.dumps(data, use_compression=True))
%timeit id_b2s.loads(id_b2s.dumps(data))
```

## Notice

I'm not a cryptoexpert, so there are some things that remain to be confirmed:

* If an attacker can control some part (or all) of the input data, is it possible for them to guess the secret key or provoke a DoS given a huge amount of attempts? (assuming the key is long enough to prevent bruteforcing in the first place, which it should since I set the minimum key size to 128b).
  > I think it is not possible but I would like an expert answer. I checked the code of different signers such as Itsdangerous, Django, etc. and they all do pretty much the same as I except they use the hmac lib.

* I always assume that no attacker can influence the instantiation of the classes, thus they can't change any setting. If someone would break all of the given recommendations and somehow manage to get attacker-controlled data to class instantiation, which settings an attacker may change to break the security of this implementation and guess the secret key? This is more of an exercise but a fun one.
  > I think that `Blake2Serializer` class is the the best target that allows more room to play since it deals with many layers: serialization, compression, encoding...

## License

**Blake2Signer** is made by [HacKan](https://hackan.net) under MPL v2.0. You are free to use, share, modify and share modifications under the terms of that [license](LICENSE).  Derived works may link back to the canonical repository: https://gitlab.com/hackancuba/blake2signer.  

    Copyright (C) 2020 HacKan (https://hackan.net)
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at https://mozilla.org/MPL/2.0/.
