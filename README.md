# Blake2Signer

The goal of this module is to provide a simple way to securely sign data using Blake2 in keyed hashing mode (read more about that in the [hashlib docs](https://docs.python.org/3/library/hashlib.html#blake2)).

 The main use case is to sign cookies or similar data. There are much better packages for other use cases or more general use cases so if you feel this module doesn't satisfy your needs consider using "itsdangerous", Django's signer, "pypaseto", "pyjwt" or others like those. My idea is to keep this module as simple as possible without much room to become a *footgun*.

This project began initially as a Gist but I decided to create a package because I think it can be useful as a small (~600 LoC counting tests), simple (quite straightforward) and fast data signer (see more below).

## Goals

* Be safe and secure.
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

* `Blake2SerializerSigner`: a signer class that handles data serialization, compression and encoding along with signing and timestamped signing.
* `Blake2Signer`: a signer class that simply salts, signs and verifies signed data as bytes or string.
* `Blake2TimestampSigner`: a signer class that simply salts, signs and verifies signed timestamped data as bytes or string.

**You should generally go for Blake2SerializerSigner**, given that it's the most versatile of the three.

In all classes you can choose between **blake2b** (default) or **blake2s** as hasher: the first one is optimized for 64b platforms and the second, for 8-32b platforms (read more about them in their [official site](https://blake2.net/)).  
The digest size is configurable with a secure minimum of 16 bytes enforced. The secret is enforced to be of a secure minimum size of 16 bytes with no size limit since it's derived to produce the key. Additionally a salt is internally generated for every signature providing non-deterministic signatures.

### Examples

The following examples are working code and should run as-is.

#### Tl; Dr

```python
"""Tl;dr example."""

from datetime import timedelta

from blake2signer import Blake2SerializerSigner
from blake2signer import errors

secret = b'secure-secret-that-nobody-knows!'
# some arbitrary data to sign
data = {'message': 'attack at dawn', 'extra': [1, 2, 3, 4]}

# Define same signer to `dumps` and `loads`.
signer = Blake2SerializerSigner(
    secret,
    max_age=timedelta(days=1),
    personalisation=b'the-cookie-signer',  # Always set it different per instance
)

# Sign and i.e. store the data in a cookie
signed = signer.dumps(data)  # Compression is enabled by default
# If compressing data turns out to be detrimental then data won't be
# compressed. If you know that from beforehand and don't need compression, you
# can disable it:
# signed = signer.dumps(data, use_compression=False)
cookie = {'data': signed}

# To verify and recover data simply use loads: you will either get the data or
# a `SignerError` subclass exception.
try:
    unsigned = signer.loads(cookie.get('data', ''))
except errors.SignedDataError:
    # Can't trust on given data
    unsigned = {}

print(unsigned)  # {'message': 'attack at dawn', 'extra': [1, 2, 3, 4]}
```

It is always a good idea to set the `personalisation` parameter which can be any arbitrarily long bytes (it defaults to the class name).  
For example if you use a signer for cookies set something like `b'cookies-signer'` or if you use it for some user-related data signing it could be `b'user-data-signer'`, or when used for signing a special value it could be `b'the-special-value-signer`, etc.

#### More Examples

Both the `secret` and `personalisation` parameters are derived so they have no size limit. This *personalisation* parameter helps defeating the abuse of using a signed stream for different signers that share the same key by changing the digest computation result. See examples of this below and read more about it in the [hashlib docs](https://docs.python.org/3/library/hashlib.html#personalization).  
Input data can always be arbitrarily long.

A secure pseudorandom salt of the maximum allowed size for the hasher is generated for each signature internally and can't be manually set. Other packages usually refer to salt as something to add to the secret to prevent signer misuse, but here we have the *personalisation* parameter for that.

As a general rule of thumb if you have highly compressible data such as human readable text, then you should enable compression. Otherwise when dealing with somewhat random data compression won't help much (but probably won't hurt either unless you're dealing with a huge amount of random data).

```python
"""Many usage examples."""

from datetime import timedelta
from time import sleep

from blake2signer import Blake2SerializerSigner
from blake2signer import Blake2Signer
from blake2signer import Blake2TimestampSigner
from blake2signer import errors

secret = b'ZnVja3RoZXBvbGljZQ'

# Serializing some data structure
data = [{'a': 'b'}, 1] * 10000  # some big data structure
print(len(data))  # 20000

signer = Blake2SerializerSigner(secret)  # without timestamp (compression by default)
signed = signer.dumps(data)
print(len(signed))  # 405  # compression helped reducing size heavily

unsigned = signer.loads(signed)
print(data == unsigned)  # True

signer = Blake2SerializerSigner(  # with timestamp
    secret,
    max_age=timedelta(weeks=1),
)
signed = signer.dumps(data, use_compression=False)  # without compression
print(len(signed))  # 160048

# You can also set the desired compression level where 1 is the fastest
# and least compressed and 9 the slowest and most compressed.
signed = signer.dumps(data, compression_level=1)
print(len(signed))  # 880  # less size reduction
# Since sample data is the same structure repeated many times it's highly
# compressible so even the lowest compression level works excellent here.
# That won't always be the case; the default value is a good balance.

unsigned = signer.loads(signed)
print(data == unsigned)  # True

signer = Blake2SerializerSigner(  # with timestamp and personalisation
    secret,
    max_age=timedelta(weeks=1),
    personalisation=b'my-cookie-signer',
)
try:
    signer.loads(signed)
except errors.InvalidSignatureError as exc:
    print(repr(exc))  # InvalidSignatureError('signature is not valid')
# Using the `personalisation` parameter made the sig to fail, thus protecting
# signed data to be loaded incorrectly.

# Signing some bytes value
data = b'facundo castro presente'

signer = Blake2Signer(  # without timestamp
    secret,
    hasher=Blake2Signer.Hashers.blake2s,  # Using Blake2s instead of Blake2b
)
signed = signer.sign(data)
print(len(signed))  # 75
unsigned = signer.unsign(signed)
print(data == unsigned)  # True

signer = Blake2Signer(secret)
signed = signer.sign(data)
print(len(signed))  # 126
unsigned = signer.unsign(signed)
print(data == unsigned)  # True

t_signer = Blake2TimestampSigner(secret)  # with timestamp
signed = t_signer.sign(data)
print(len(signed))  # 133
unsigned = t_signer.unsign(signed, max_age=10)  # signature is valid if its not
# older than this many seconds (10)
print(data == unsigned)  # True

# The timestamp is checked when unsigning so that if that many seconds
# since the data was signed passed then the signature is considered
# expired. The signature is verified before checking the timestamp so it
# must be valid too.
# You can use both an integer or a float to represent seconds or a
# timedelta with the time value you want.
signed = t_signer.sign(data)
sleep(2)
try:
    t_signer.unsign(signed, max_age=timedelta(seconds=2))
except errors.ExpiredSignatureError as exc:
    print(repr(exc))  # ExpiredSignatureError('signed data has expired')

# Preventing misuse of signed data
try:
    t_signer.unsign(signer.sign(data), max_age=5.5)
except errors.InvalidSignatureError as exc:
    print(repr(exc))  # InvalidSignatureError('signature is not valid')
try:
    signer.unsign(t_signer.sign(data))
except errors.InvalidSignatureError as exc:
    print(repr(exc))  # InvalidSignatureError('signature is not valid')
# You can't mix and match signers, and that's on purpose. This is because
# internally the personalisation parameter, which changes the computed
# digest, is set to the class name. However you could find your way to
# trick one class into accepting data generated by the other but you
# really shouldn't!.
```

Even though both `Blake2Signer` and `Blake2TimestampSigner` accept data as string you should use bytes instead: both classes will try to convert any given string to bytes **assuming it's UTF-8 encoded** which might not be correct; if you are certain that the string given is UTF-8 then it's OK, otherwise ensure encoding the string correctly and using bytes instead.

#### Using a custom JSON encoder or custom serializer

You can use a custom JSON encoder or even a custom serializer such as [msgpack](https://pypi.org/project/msgpack/) which is very efficient in size and performance, much better than JSON (half resulting size and more than twice as fast) so it is an excellent choice for a serializer. For keeping JSON as serializer a better choice than the standard library is [orjson](https://github.com/ijl/orjson) which is faster.

```python
"""Sample of custom JSON encoder and custom serializer."""

import typing
from decimal import Decimal
from json import JSONEncoder

import msgpack

from blake2signer import Blake2SerializerSigner
from blake2signer.serializers import JSONSerializer
from blake2signer.serializers import SerializerInterface

# Custom JSON encoder
class DecimalJSONEncoder(JSONEncoder):

    def default(self, o):
        if isinstance(o, Decimal):
            return str(o)

        return super().default(o)

class MyJSONSerializer(JSONSerializer):

    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        return super().serialize(data, cls=DecimalJSONEncoder, **kwargs)

secret = b'super-secret-value'
signer = Blake2SerializerSigner(secret, serializer=MyJSONSerializer)

data = {'points': [1, 2, Decimal('3.4')]}
unsigned = signer.loads(signer.dumps(data))
print(unsigned)  # {'points': [1, 2, '3.4']}

# Custom serializer with msgpack (same idea would be for orjson)
class MsgpackSerializer(SerializerInterface):

    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Serialize given data as msgpack."""
        return msgpack.packb(data)

    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Unserialize given msgpack data."""
        return msgpack.unpackb(data)

signer = Blake2SerializerSigner(secret, serializer=MsgpackSerializer)
data = {'points': [1, 2, 3.4]}
signed = signer.dumps(data)
print(signed)  # ....gaZwb2ludHOTAQLLQAszMzMzMzM
unsigned = signer.loads(signed)
print(unsigned)  # {'points': [1, 2, 3.4]}
```

`Blake2SerializerSigner` is quite flexible and can receive custom serializer, compressor or encoder. You could i.e. create a custom base62 encoder simply inheriting from `EncoderInterface`, or a custom bzip compressor inheriting from `CompressorInterface`. You don't need to handle or worry about exceptions: those are caught by the caller class.

On the other hand you can create your own *SerializerSigner* using provided `Blake2SerializerSignerBase` and/or any of the mixins: `SerializerMixin`, `CompressorMixin`, `EncoderMixin` or even creating your own mixin inheriting from `Mixin`.

```python
"""Custom serializer signer class example."""

import typing

from blake2signer.serializers import EncoderMixin


class MySerializerSigner(EncoderMixin):

    def dumps(self, data: typing.Any) -> str:
        encoded = self._encode(self._force_bytes(data))

        return self._dumps(encoded).decode()

    def loads(self, signed_data: typing.AnyStr) -> typing.Any:
        unsigned = self._loads(self._force_bytes(signed_data))

        decoded = self._decode(unsigned)

        return decoded.decode()

secret = b'super-secret-value'
signer = MySerializerSigner(secret)
data = 'memoria y justicia'
signed = signer.dumps(data)
print(signed)  # ....bWVtb3JpYSB5IGp1c3RpY2lh
print(signer.loads(signed) == data)  # True
```

##### I need to work with raw bytes but I want compression and encoding

Usually to work with bytes one can choose to use either `Blake2Signer` or `Blake2TimestampSigner`. However, if you also want to have compression and encoding, you need `Blake2SerializerSigner`. The problem now is that JSON doesn't support bytes so the class as-is won't work. There are two solutions:

1. Use the `MsgpackSerializer` created above given that *msgpack* does handle bytes serialization.
1. Create your custom serializer that doesn't actually serializes to use it with `Blake2SerializerSigner`.
1. Create your custom class inheriting from `EncoderMixin` and `CompressorMixin`.

Here are those examples:

```python
"""Sample of a custom encoder compressor signer class."""

import typing

from blake2signer.serializers import CompressorMixin
from blake2signer.serializers import EncoderMixin


class MyEncoderCompressorSigner(EncoderMixin, CompressorMixin):
 
    def dumps(self, data: typing.AnyStr) -> str:
        data_bytes = self._force_bytes(data)
        compressed, _ = self._compress(data_bytes, level=6)
        encoded = self._encode(compressed)
        signed = self._dumps(encoded).decode()

        return signed
 
    def loads(self, signed_data: typing.AnyStr) -> bytes:
        signed_bytes = self._force_bytes(signed_data)
        unsigned = self._loads(signed_bytes)
        decoded = self._decode(unsigned)
        decompressed = self._decompress(decoded)
 
        return decompressed


secret = b'super-secret-value'
signer = MyEncoderCompressorSigner(secret)
data = b'acab' * 100
signed = signer.dumps(data)
print(len(signed) < len(data))  # True
print(signer.loads(signed) == data)  # True
```

```python
"""Sample of a custom serializer that doesn't serializes."""

import typing

from blake2signer import Blake2SerializerSigner
from blake2signer.serializers import SerializerInterface
from blake2signer.utils import force_bytes


class MySerializer(SerializerInterface):

    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Convert given data to bytes."""
        return force_bytes(data)

    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Unserialize given serialized data."""
        return data


secret = b'super-secret-value'
signer = Blake2SerializerSigner(secret, serializer=MySerializer)
data = b'acab' * 100
signed = signer.dumps(data)
print(len(signed) < len(data))  # True
print(signer.loads(signed) == data)  # True
```

#### Real use case example

Sign cookies in a FastAPI/Starlette middleware.

```python
"""Sample use case: sign cookies in a FastAPI/Starlette middleware."""

from datetime import timedelta

from fastapi import Request
from fastapi import Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.base import RequestResponseEndpoint

from blake2signer import Blake2SerializerSigner
from blake2signer.errors import SignedDataError

# from .messages import Messages  # Some class that has the data we want to sign
class Messages:

    def to_dict(self) -> dict:
        return self.__dict__

    @classmethod
    def from_dict(cls, data: dict) -> 'Messages':
        return cls(**data)

# In this example, that class can be converted to/read from dict.
# It doesn't need to be exactly a dict but any Python type that
# can be JSON encodable (string, number, list/tuple or dict).

SECRET_KEY: bytes = b'myverysecretsecret'
COOKIE_TTL: timedelta = timedelta(days=5)
COOKIE_NAME: str = 'data_cookie'


class CookieHTTPMiddleware(BaseHTTPMiddleware):

    @property
    def _signer(self) -> Blake2SerializerSigner:
        return Blake2SerializerSigner(
            SECRET_KEY,
            max_age=COOKIE_TTL,
            personalisation=b'cookie_http_middleware',
        )

    def get_cookie_data(self, request: Request) -> Messages:
        signed_data = request.cookies.get(COOKIE_NAME, '')
        messages_data = self._signer.loads(signed_data)  # may raise SignedDataError
        messages = Messages.from_dict(messages_data)
        return messages

    def set_cookie_data(self, messages: Messages, response: Response) -> None:
        data = messages.to_dict()
        signed_data = self._signer.dumps(data)
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
        except SignedDataError:  # some tampering, maybe we changed the secret...
            request.state.messages = Messages()

        response = await call_next(request)

        # You may want to implement some change detection mechanism to avoid
        # writing cookies in every response.
        # if changed(request.state.messages):
        self.set_cookie_data(request.state.messages, response)

        return response
```

## Comparison with other libs

It's easy to compare this lib to, say, [itsdangerous](https://itsdangerous.palletsprojects.com/en/1.1.x) and [django](https://www.djangoproject.com). Generally speaking its as fast or a bit faster than the other libs, so you should choose one or the other based on usability and fitting-your-needs rather than performance.

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

from blake2signer import Blake2SerializerSigner
from blake2signer import Blake2Signer

secret = b'1' * 16
data = [{'a': 'b'}, 1] * 100000  # some big data structure
datas = json.dumps(data)
datab = datas.encode()

b2s = Blake2Signer(secret)
b2ss = Blake2SerializerSigner(secret)
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
id_b2s = URLSafeSerializer(secret, signer_kwargs={'digest_method': blake2b})

# Using ipython:
print('b2s')
%timeit b2s.unsign(b2s.sign(datab))
print('id_b2')
%timeit id_b2.unsign(id_b2.sign(datab))
print('id_s1')
%timeit id_s1.unsign(id_s1.sign(datab))
print('id_s256')
%timeit id_s256.unsign(id_s256.sign(datab))
print('id_s384')
%timeit id_s384.unsign(id_s384.sign(datab))
print('id_s512')
%timeit id_s512.unsign(id_s512.sign(datab))
print('djs_b2')
%timeit djs_b2.unsign(djs_b2.sign(datas))
print('djs_s1')
%timeit djs_s1.unsign(djs_s1.sign(datas))
print('djs_s256')
%timeit djs_s256.unsign(djs_s256.sign(datas))
print('djs_s384')
%timeit djs_s384.unsign(djs_s384.sign(datas))
print('djs_s512')
%timeit djs_s512.unsign(djs_s512.sign(datas))
print('b2ss')
%timeit b2ss.loads(b2ss.dumps(data))
print('id_b2s')
%timeit id_b2s.loads(id_b2s.dumps(data))
```

## Notice

I'm not a cryptoexpert, so there are some things that remain to be confirmed:

* If an attacker can control some part (or all) of the input data, is it possible for them to guess the secret key or provoke a DoS given a huge amount of attempts? (assuming the key is long enough to prevent bruteforcing in the first place, which it should since I set the minimum key size to 128b).
  > I think it is not possible but I would like an expert answer. I checked the code of different signers such as Itsdangerous, Django, etc. and they all do pretty much the same as I except they use the hmac lib.

* I always assume that no attacker can influence the instantiation of the classes, thus they can't change any setting. If someone would break all of the given recommendations and somehow manage to get attacker-controlled data to class instantiation, which settings an attacker may change to break the security of this implementation and guess the secret key? This is more of an exercise but a fun one.
  > I think that `Blake2SerializerSigner` class is the the best target that allows more room to play since it deals with many layers: serialization, compression, encoding...

## License

**Blake2Signer** is made by [HacKan](https://hackan.net) under MPL v2.0. You are free to use, share, modify and share modifications under the terms of that [license](LICENSE).  Derived works may link back to the canonical repository: https://gitlab.com/hackancuba/blake2signer.

    Copyright (C) 2020 HacKan (https://hackan.net)
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at https://mozilla.org/MPL/2.0/.
