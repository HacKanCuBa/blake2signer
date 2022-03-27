# Examples

The following examples are working code and should run as-is.

## Tl; Dr

```python
"""Tl;dr example."""

from datetime import timedelta

from blake2signer import Blake2SerializerSigner
from blake2signer import errors

secret = b'secure-secret-that-nobody-knows!'
# Some arbitrary data to sign
data = {'user_id': 1, 'is_admin': True, 'username': 'hackan'}

signer = Blake2SerializerSigner(
    secret,
    max_age=timedelta(days=1),  # Add a timestamp to the signature
    personalisation=b'the-cookie-signer',
)

# Sign and i.e. store the data in a cookie
signed = signer.dumps(data)  # Compression is enabled by default
# If compressing data turns out to be detrimental then data won't be
# compressed. If you know that from beforehand and don't need compression, you
# can disable it:
# signed = signer.dumps(data, compress=False)
# Additionally, you can force compression nevertheless:
# signed = signer.dumps(data, force_compression=True)
cookie = {'data': signed}

# To verify and recover data simply use `loads`: you will either get the data or
# a `SignerError` subclass exception.
try:
    unsigned = signer.loads(cookie.get('data', ''))
except errors.SignedDataError:
    # Can't trust on given data
    unsigned = {}

print(unsigned)  # {'user_id': 1, 'is_admin': True, 'username': 'hackan'}
```

!!! tip "Controlling exceptions"
    When using `unsign` or `loads` always wrap them in a `try ... except errors.SignedDataError` block to catch all exceptions raised by those methods. Moreover, [all exceptions raised by this lib](errors.md) are subclassed from `SignerError`.  
    Alternatively, check each method's docs and catch specific exceptions.

!!! tip "Using personalisation"
    It is always a good idea to set the [`personalisation` parameter](details.md#about-salt-and-personalisation): it helps to defeat the abuse of using a signed stream for different signers that share the same key by changing the digest computation result. For example if you use a signer for cookies set something like `b'cookies-signer'` or if you use it for some user-related data signing it could be `b'user data signer'`, or when used for signing a special value it could be `b'the-special-value-signer`, etc.

!!! tip "A good secret"
    Ensure that the [secret](details.md#about-the-secret) has at least 256 bits of cryptographically secure pseudorandom data, and **not** some manually splashed letters!

## Real use case

Sign cookies in a FastAPI/Starlette middleware.

!!! example "A better example"
    Even though this code does work as-is, there's a better, easier to implement example of cookie signing middleware as a [snippet](https://gitlab.com/hackancuba/blake2signer/-/snippets/2236491)!

!!! tip "There's a package for this, too"
    Check out the `asgi-signing-middleware` [package](https://pypi.org/project/asgi-signing-middleware/) which does this, and more :)

```python
"""Sample use case: sign cookies in a FastAPI/Starlette middleware."""

from datetime import timedelta
from functools import cached_property

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

    @cached_property  # Only in Python 3.8+
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

## Signing data structures

You can quickly get any python object serialized and signed using `Blake2SerializerSigner`, which additionally compresses and encodes the output by default. It uses a JSON serializer by default, but it can be changed easily.

```python
"""Signing a data structure that requires serialization."""

from blake2signer import Blake2SerializerSigner

secret = b'ZnVja3RoZXBvbGljZQ'

data = {
    'username': 'hackan',
    'id': 1,
    'posts': [{'title': '...', 'body': '...'}] * 100  # Some big data structure
}
print(len(str(data)))  # 3342  # Approximated flattened size for reference

signer = Blake2SerializerSigner(secret)
signed = signer.dumps(data)
print(len(signed))  # 175  # Compression helped to reduce size heavily

unsigned = signer.loads(signed)
print(data == unsigned)  # True
```

!!! tip "Favor bytes over string"
    Even though `Blake2SerializerSigner` accepts parameters as string (`secret`, `personalisation`, `separator` and `compression_flag`) you should use bytes instead: it will try to convert any given string to bytes **assuming it's UTF-8 encoded** which might not be correct (an `errors.ConversionError` exception is raised); if you are certain that the string given is UTF-8 then it's OK, otherwise ensure encoding the string correctly and using bytes instead.

### Using non-serializer signers

You may not want all that `Blake2SerializerSigner` does and instead require the serialization to be plain in the signature, perhaps to [split the signature](#splitting-signatures) and be able to read the payload from JS. In this situation you may want to use `Blake2Signer`, or `Blake2TimestampSigner` if you also require to limit the lifetime of the signature.

```python
"""Signing a serialized data structure."""

import json

from blake2signer import Blake2Signer
from blake2signer.serializers import JSONSerializer

secret = b'ZnVja3RoZXBvbGljZQ'
data = {
    'username': 'hackan',
    'id': 1,
    'is_admin': True,
}

serialized_data = json.dumps(data)

signer = Blake2Signer(secret)
signed = signer.sign(serialized_data)
# In this case both the signature and payload are ASCII, so you can convert the
# values to string safely
print(signed.decode())  # ....{"username": "hackan", "id": 1, "is_admin": true}

unsigned = signer.unsign(signed)
print(serialized_data == unsigned)  # True

# Alternatively, use the JSONSerializer (it uses compact encoding)
serialized_data = JSONSerializer().serialize(data)
signed = signer.sign(serialized_data)
print(signed.decode())  # ....{"username":"hackan","id":1,"is_admin":true}

# New in v2.0.0
# The signature can be split in parts, don't do it "by hand"
signature = signer.sign_parts(serialized_data)
print(signature)
# Blake2Signature(signature=b'...', data=b'{"username": "hackan", "id": 1, "is_admin": true}')

# Now you can transmit the parts separately and then check the signature
unsigned = signer.unsign_parts(signature)
print(serialized_data == unsigned)  # True
```

### Changing the serializer

There are two [serializers provided by this package](details.md#encoders-serializers-and-compressors): a JSON serializer (default) and a Null serializer, which is useful to [deal with bytes using `Blake2SerializerSigner`](#using-the-nullserializer).

```python
"""Changing the serializer in Blake2SerializerSigner."""

from blake2signer import Blake2SerializerSigner
from blake2signer.serializers import JSONSerializer
from blake2signer.serializers import NullSerializer

secret = 'may the force be with you'
data = 'always'

signer1 = Blake2SerializerSigner(secret, serializer=JSONSerializer)  # Default
signed = signer1.dumps(data)
unsigned = signer1.loads(signed)
print(data == unsigned)  # True

# The NullSerializer is useful to use this class with bytes (see example below)
signer2 = Blake2SerializerSigner(secret, serializer=NullSerializer)
signed = signer2.dumps(data)
unsigned = signer2.loads(signed)
print(data == unsigned.decode())  # True

# Mixing the signers is protected as always
signer1.loads(signed)
# blake2signer.errors.InvalidSignatureError: signature is not valid
```

!!! tip "Custom serializer"
    You can [create a custom serializer](#using-a-custom-serializer).

### Using a custom JSON encoder

You can use a custom JSON encoder to serialize values that are not supported by JSON, such as i.e. `bytes` or `Decimal`.

!!! note
    When unserializing, the information for custom types is lost.

=== "v2"

    ```python
    """Sample of custom JSON encoder for v2+."""

    from decimal import Decimal
    from json import JSONEncoder

    from blake2signer import Blake2SerializerSigner


    class CustomJSONEncoder(JSONEncoder):

        def default(self, o):
            if isinstance(o, Decimal):
                return str(o)
            elif isinstance(o, bytes):
                return o.decode()

            return super().default(o)


    secret = 'que-paso-con-Tehuel'
    data = [1, b'2', Decimal('3.4')]

    signer = Blake2SerializerSigner(secret)
    # New in v2.0.0
    # You can pass any keyword argument to the serializer directly from `dumps`
    signed = signer.dumps(data, serializer_kwargs={'cls': CustomJSONEncoder})

    unsigned = signer.loads(signed)
    print(unsigned)  # [1, '2', '3.4']
    ```

=== "v1"

    For versions older than v2, you need to create a custom serializer from the JSONSerializer:

    ```python
    """Sample of custom JSON encoder for versions < v2."""

    import typing
    from decimal import Decimal
    from json import JSONEncoder

    from blake2signer import Blake2SerializerSigner
    from blake2signer.serializers import JSONSerializer


    class CustomJSONEncoder(JSONEncoder):

        def default(self, o):
            if isinstance(o, Decimal):
                return str(o)
            elif isinstance(o, bytes):
                return o.decode()

            return super().default(o)


    class MyJSONSerializer(JSONSerializer):

        def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
            return super().serialize(data, cls=CustomJSONEncoder, **kwargs)


    secret = 'que-paso-con-Tehuel'
    data = [1, b'2', Decimal('3.4')]

    signer = Blake2SerializerSigner(secret, serializer=MyJSONSerializer)

    unsigned = signer.loads(signer.dumps(data))
    print(unsigned)  # [1, '2', '3.4']
    ```

!!! warning
    Using a custom JSON encoder to deal with data that is pure bytes is a bad idea performance-wise. You should prefer using the [`NullSerializer`](#using-the-nullserializer) or [other signers](#signing-raw-bytes-or-strings) instead.

### Using a custom serializer

You can use a custom serializer such as [msgpack](https://pypi.org/project/msgpack/) which is very efficient, much better than JSON (half resulting size and more than twice as fast), so it is an excellent choice for a serializer. For keeping JSON as serializer a better choice than the standard library is [orjson](https://github.com/ijl/orjson) which is faster.

All you need to do is implement `SerializerInterface`, and define how is your serializer serializing and unserializing. That's it.

!!! warning
    **Never** use `pickle` as serializer given than if for some implementation error a malicious user can sign arbitrary data, then unsigning it will cause code execution (JSON and msgpack are safe against such situations).

```python
"""Creating a custom serializer."""

import typing

import msgpack

from blake2signer import Blake2SerializerSigner
from blake2signer.interfaces import SerializerInterface


# Custom serializer with msgpack (same idea would be for orjson)
class MsgpackSerializer(SerializerInterface):
    """Msgpack serializer."""

    def serialize(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        """Serialize given data as msgpack."""
        return msgpack.packb(data, **kwargs)

    def unserialize(self, data: bytes, **kwargs: typing.Any) -> typing.Any:
        """Unserialize given msgpack data."""
        return msgpack.unpackb(data, **kwargs)


secret = b'que-paso-con-Tehuel'
data = {'data': [1, b'2', 3.4]}

signer = Blake2SerializerSigner(secret, serializer=MsgpackSerializer)
signed = signer.dumps(data)
print(signed)  # ....gaRkYXRhkwHEATLLQAszMzMzMzM

unsigned = signer.loads(signed)
print(unsigned)  # {'data': [1, b'2', 3.4]}
print(data == unsigned)  # True
```

### Compressing data

There are several options regarding the compression capabilities of `Blake2SerializerSigner`. By default, it will check if compressing given data is working out positively or not, and may decide to not compress after all. This behaviour can be changed to not compress at all or force the compression nevertheless. The [compression level](details.md#compression-level) can also be tweaked to your needs.

```python
"""Signing a data structure and playing with compression capabilities."""

from secrets import token_hex

from blake2signer import Blake2SerializerSigner
from blake2signer.compressors import GzipCompressor

secret = b'ZnVja3RoZXBvbGljZQ'
data = {
    'username': 'hackan',
    'id': 1,
    'posts': [{'title': '...', 'body': '...'}] * 100  # Some big data structure
}
print(len(str(data)))  # 3342  # Approximated flattened size for reference

signer = Blake2SerializerSigner(
    secret,
    compressor=GzipCompressor,  # Gzip compressor instead of the default Zlib
)
signed = signer.dumps(data, compress=False)  # Without compression
print(len(signed))  # 3957  # Significantly bigger than actual data

# As a general rule of thumb if you have highly compressible data such
# as human-readable text, then you should leave compression enabled.
# Otherwise, when dealing with somewhat random data compression won't
# help much (but probably won't hurt either unless you're dealing with
# a huge amount of random data). A check is done when compression is
# enabled and if it turns out to be detrimental then data won't be
# compressed, so you can leave it on as it is by default (read about compression
# ratio further below).
# In this example dumping the output of `token_hex` won't be compressed
# even though it is enabled.
print(len(signer.dumps(token_hex(16))) > len(signer.dumps('a' * 16)))  # True

# New in v1.1.0
# However, you can force compressing the data, even if the result might actually
# be bigger than it was initially (detrimental compression).
random_data = token_hex(16)
print(
    len(signer.dumps(random_data, force_compression=True)) >
    len(signer.dumps(random_data))
)  # True

# You can also set the desired compression level where 1 is the fastest
# and least compressed and 9 the slowest and most compressed (the default value
# is up to the compressor).
signed = signer.dumps(data, compression_level=9)
print(len(signed))  # 175
signed = signer.dumps(data, compression_level=1)
print(len(signed))  # 197  # Less size reduction, but compression is faster
# Since sample data is the same structure repeated many times, it's highly
# compressible so even the lowest compression level works excellent here.
# That won't always be the case; the default value is usually a good balance.

unsigned = signer.loads(signed)
print(data == unsigned)  # True
```

### Changing the compression ratio

!!! info "New in v2.0.0"

You can set the compression ratio to your needs, and define when is data considered to be sufficiently compressed. This plays very well when [using a custom compressor](#using-a-custom-compressor), and lets you tweak the auto-compression mechanism. It can be any value between 0 and 99. The default value is 5, meaning that data is considered sufficiently compressed when its size is reduced more than 5%.

```python
"""Changing the compression ratio."""

from blake2signer import Blake2SerializerSigner

secret = b'ZnVja3RoZXBvbGljZQ'
data = 'acab' * 4  # Only somewhat compressible

signer1 = Blake2SerializerSigner(secret)  # Default compression ratio of 5
signed1 = signer1.dumps(data)  # Compressed
signed2 = signer1.dumps(data, compress=False)  # Not compressed

signer2 = Blake2SerializerSigner(secret, compression_ratio=20)
signed3 = signer2.dumps(data)  # Won't compress because of ratio

print(
    len(signed1), '<', len(signed2), '=', len(signed3), ':',
    len(signed1) < len(signed2) == len(signed3),
)  # 61 < 63 = 63 : True
```

!!! note
    For versions older than v2, *compression ratio* can be set through the class attribute `COMPRESSION_RATIO`. Note that this change affects all instances of the class, which is why said value was refactored to be an instance attribute.

### Changing the compressor

There are two [compressors provided by this package](details.md#encoders-serializers-and-compressors): a Zlib compressor (default) and a Gzip compressor.

```python
"""Changing the compressor in Blake2SerializerSigner."""

from blake2signer import Blake2SerializerSigner
from blake2signer.compressors import GzipCompressor
from blake2signer.compressors import ZlibCompressor

secret = 'may the force be with you'
data = 'always'

signer1 = Blake2SerializerSigner(secret, compressor=ZlibCompressor)  # Default
signed = signer1.dumps(data)
unsigned = signer1.loads(signed)
print(data == unsigned)  # True

# The Gzip compressor may be faster, with compression being relatively worst.
signer2 = Blake2SerializerSigner(secret, compressor=GzipCompressor)
signed = signer2.dumps(data)
unsigned = signer2.loads(signed)
print(data == unsigned)  # True

# Mixing the signers is protected as always
signer1.loads(signed)
# blake2signer.errors.InvalidSignatureError: signature is not valid
```

!!! tip "Custom compressor"
    You can [create a custom compressor](#using-a-custom-compressor).

### Using a custom compressor

You can use custom compressors such as BZ2 or LZMA, or any other. All you need to do is implement `CompressorInterface`, and define how is your compressor compressing and decompressing. That's it.

!!! note
    If you get an import error for `bz2` then [your python build doesn't support it](https://stackoverflow.com/questions/12806122/missing-python-bz2-module/12806325#12806325).

```python
"""Creating a custom compressor."""

import bz2

from blake2signer import Blake2SerializerSigner
from blake2signer.interfaces import CompressorInterface


class Bz2Compressor(CompressorInterface):
    """Bzip2 compressor."""

    @property
    def default_compression_level(self) -> int:  # New in 2.1.0
        """Get the default compression level."""
        return 9  # According to https://docs.python.org/3/library/bz2.html#bz2.compress

    def compress(self, data: bytes, *, level: int) -> bytes:
        """Compress given data."""
        return bz2.compress(data, compresslevel=level)

    def decompress(self, data: bytes) -> bytes:
        """Decompress given compressed data."""
        return bz2.decompress(data)


secret = b'we do not forget...'
data = [i for i in range(100)]
print(len(str(data)))  # 390

signer = Blake2SerializerSigner(secret, compressor=Bz2Compressor)
signed = signer.dumps(data)
print(signed)  # ...oMgclQNA3KgNhqVAODMqAOnkqAFsVUALlR-x_F3JFOFCQjBBOmw
print(len(signed))  # 195

unsigned = signer.loads(signed)
print(data == unsigned)  # True
```

### Changing the compression flag

!!! info "New in v2.0.0"

If you are limited to a certain character range in your signed data transport, you can set the compression flag character to any value needed (as well as [the encoder](#changing-the-encoder) and the [separator character](#changing-the-separator-character)).  
It is used internally to mark a compressed payload to prevent [zip bombs](https://en.wikipedia.org/wiki/Zip_bomb), and it can be any ASCII character, but it must not belong to the encoder alphabet to be able to unequivocally recognize it.

!!! info
    It defaults to a dot (`.`).

```python
"""Changing the compression flag."""

from blake2signer import Blake2SerializerSigner

secret = b'setec astronomy.'
data = 'too many secrets'

signer = Blake2SerializerSigner(secret, compression_flag=b'!')
signed = signer.dumps(data, force_compression=True)
print(signed)  # ....!eJxTKsnPV8hNzKtUKE5NLkotKVYCADzjBoU
print(data == signer.loads(signed))  # True
```

!!! note
    For versions older than v2, the *compression flag* can be set through the class attribute `COMPRESSION_FLAG`. Note that this change affects all instances of the class, which is why said value was refactored to be an instance attribute.

### Dealing with files

!!! info "New in v2.0.0"

`Blake2SerializerSigner` has two convenient methods to deal with files: `dump` (write signed data to file) and `load` (read signed data from file). These methods may raise `errors.FileError` while reading from/writing to the file.

```python
"""Dealing with files using Blake2SerializerSigner."""

from blake2signer import Blake2SerializerSigner

secret = b'using crypto is not a crime'
data = 'free Ola Bini!!'

signer = Blake2SerializerSigner(secret)

with open('somefile', 'wt') as file:
    signed = signer.dump(data, file)  # Signed data returned for convenience
    print(signed)  # ....ImZyZWUgT2xhIEJpbmkhISI

with open('somefile', 'rt') as file:
    print(signer.load(file))  # free Ola Bini!!
```

!!! note "Text and binary modes supported"
    Both opening modes are supported, so given file can be opened in text or binary mode indistinctly.

```python
"""Dealing with files with additional content using Blake2SerializerSigner."""

import io

from blake2signer import Blake2SerializerSigner

secret = 'free Chelsea 🤘'
data = {
    'META': {'version': 1},
    'uid': 'c61df3b7-66db-438a-9246-c77861597168',
    'username': 'hackan',
}

signer = Blake2SerializerSigner(secret)

file = io.BytesIO()
file.write(b'unsigned metadata: {"version": 1}\n')

# We need to remember the initial position to recover data later
initial_position = file.tell()

# `dump` will start writing from the current position
signed = signer.dump(data, file, compression_level=9)
print(file.tell() == (initial_position + len(signed)))  # True

# `load` will read the entirety of the file from the current position
file.seek(initial_position)
print(signer.load(file))
# {'META': {'version': 1}, 'uid': 'c61df3b7-66db-438a-9246-c77861597168', 'username': 'hackan'}

file.seek(0)
print(file.read().decode())
# unsigned metadata: {"version": 1}
# ....eyJNRVRBIjp7InZlcnNpb24iOjF9LCJ1aWQiOiJjNjFkZjNiNy02NmRiLTQzOGEtOTI0Ni1jNzc4NjE1OTcxNjgiLCJ1c2VybmFtZSI6ImhhY2thbiJ9
```

!!! note
    Both methods uses the file as-is: this means that for `dump`, data is written at the current position (so the cursor advances equally to the written size), and for `load`, data is read entirely from the current position (so the cursor will sit at the end).

## Signing raw bytes or strings

Sometimes you don't have to deal with a complex data structure and all you need is to do is sign a simple string, or the output of a computation as bytes, without any serialization. You could serialize the string, but the performance impact is big, so it would not be recommended.

```python
"""Signing data as raw bytes or strings."""

from datetime import timedelta
from time import sleep

from blake2signer import Blake2Signer
from blake2signer import Blake2TimestampSigner
from blake2signer import errors
from blake2signer.encoders import HexEncoder

secret = b'ZnVja3RoZXBvbGljZQ'
data = b'facundo castro presente'

signer = Blake2Signer(
    secret,
    hasher=Blake2Signer.Hashers.blake2s,  # Using Blake2s instead of Blake2b
    encoder=HexEncoder,  # Using the hex encoder for the signature (new in v2.0.0)
    digest_size=32,  # Setting the maximum digest size for Blake2s
)
signed = signer.sign(data)
print(signed)  # The signature only has hex characters (data is not encoded!)

unsigned = signer.unsign(signed)
print(data == unsigned)  # True

# Using the timestamp signer
t_signer = Blake2TimestampSigner(secret)
signed = t_signer.sign(data)
print(len(signed))  # 69

unsigned = t_signer.unsign(signed, max_age=10)
# Signature is valid if it's not older than that many seconds (10)
print(data == unsigned)  # True

# The timestamp is checked when unsigning so that if that many seconds
# since the data was signed passed then the signature is considered
# expired. The signature is verified before checking the timestamp so it
# must be valid too.
# You can use both an integer, or a float to represent seconds or a timedelta
# with the time value you want.
signed = t_signer.sign(data)
max_age = timedelta(seconds=2)
sleep(2)

try:
    t_signer.unsign(signed, max_age=max_age)
except errors.ExpiredSignatureError as exc:
    print(repr(exc), 'expired on', (exc.timestamp + max_age).isoformat())
    # ExpiredSignatureError('signature has expired, age 2.0024588108062744 > 2.0 seconds') expired on 2021-04-24T21:56:47+00:00
# The `ExpiredSignatureError` exception contains the signature timestamp as an
# aware datetime object (in UTC) in case you need that information to display
# something meaningful to the user.

# New in v2.4.0
# If `max_age` is None, then the timestamp is not checked (but the signature is
# always checked!).
unsigned = t_signer.unsign(signed, max_age=None)
print(data == unsigned)  # True
```

!!! tip "Favor bytes over string"
    Even though both `Blake2Signer` and `Blake2TimestampSigner` accepts data and parameters (`secret`, `personalisation` and `separator`) as string you should use bytes instead: both classes will try to convert any given string to bytes **assuming it's UTF-8 encoded** which might not be correct (an `errors.ConversionError` exception is raised); if you are certain that the string given is UTF-8 then it's OK, otherwise ensure encoding the string correctly and using bytes instead. Additionally, when *unsigned*, the data type will be bytes and not string (again, you can convert it if you know the encoding).

### I need to work with raw bytes, but I want compression and encoding

Usually to work with bytes or string one can choose to use either `Blake2Signer` or `Blake2TimestampSigner`. However, if you also want to have compression and encoding, you need `Blake2SerializerSigner`. The problem now is that JSON doesn't support bytes, so the class as-is won't work. There are a couple of solutions:

1. Use the `NullSerializer` from the `serializers` submodule with `Blake2SerializerSigner` ([see example](#using-the-nullserializer) below).
1. Create a custom JSON encoder that encodes bytes ([see example](#using-a-custom-json-encoder) above).
1. Use the `MsgpackSerializer` given that *msgpack* does handle bytes serialization ([see example](#using-a-custom-serializer) above).
1. Create a custom class inheriting from `CompressorMixin` and `Blake2SerializerSignerBase` - which already contains `EncoderMixin` - ([see example](#creating-a-custom-serializersigner-class) below).

#### Using the NullSerializer

!!! info "New in v2.0.0"

The `NullSerializer` is useful when one needs to deal with bytes but want compression and encoding capabilities. Otherwise `Blake2Signer` or `Blake2TimestampSigner` should be preferred.

```python
"""Using the NullSerializer with Blake2SerializerSigner."""

from blake2signer import Blake2SerializerSigner
from blake2signer.serializers import NullSerializer

secret = b'ZnVja3RoZXBvbGljZQ'
data = b'facundo castro presente'

signer = Blake2SerializerSigner(
    secret,
    serializer=NullSerializer,  # A serializer that doesn't serialize
)
signed = signer.dumps(data)
print(signed)  # ....ZmFjdW5kbyBjYXN0cm8gcHJlc2VudGU

unsigned = signer.loads(signed)
print(data == unsigned)  # True
```

!!! tip
    For versions older than v2, you can copy [the code of the `NullSerializer`](https://gitlab.com/hackancuba/blake2signer/-/blob/develop/blake2signer/serializers.py) and [create it as custom serializer](#using-a-custom-serializer) .

## Limiting signature lifetime

You can limit the lifetime of the signature with both `Blake2SerializerSigner` and `Blake2TimestampSigner`: a timestamp is appended to the signature and is checked to the current time when verifying it.

```python
"""Signing a data structure that requires a limited lifetime."""

import json
from datetime import timedelta

from blake2signer import Blake2SerializerSigner
from blake2signer import Blake2TimestampSigner
from blake2signer import errors

secret = b'ZnVja3RoZXBvbGljZQ'
data = {
    'username': 'hackan',
    'id': 1,
    'posts': [{'title': '...', 'body': '...'}] * 100  # Some big data structure
}
ttl = timedelta(hours=1)  # int or float value can also be used, as seconds

signer = Blake2SerializerSigner(
    secret,
    max_age=ttl,  # With timestamp
)
signed = signer.dumps(data)
print(len(signed))  # 166  # Compression is active by default

try:
    unsigned = signer.loads(signed)
except errors.ExpiredSignatureError as exc:
    # Should an hour had passed, then this exception would be raised
    print(repr(exc), 'expired on', (exc.timestamp + ttl).isoformat())
    # ExpiredSignatureError('signature has expired, age ... > 3600.0 seconds') expired on 2021-05-19T22:50:27+00:00
else:
    print(data == unsigned)  # True

# The same goes for Blake2TimestampSigner, but without compression nor
# serialization capabilities, it only handles raw bytes and strings
signer = Blake2TimestampSigner(secret)
serialized_data = json.dumps(data)
signed = signer.sign(serialized_data)
print(len(signed))  # 3388  # No compression capabilities

try:
    # `max_age` can be either a timedelta, or an integer or float expressing seconds
    unsigned = signer.unsign(signed, max_age=ttl.total_seconds())
except errors.ExpiredSignatureError as exc:
    # Should an hour had passed, then this exception would be raised
    print(repr(exc), 'expired on', (exc.timestamp + ttl).isoformat())
    # ExpiredSignatureError('signature has expired, age ... > 3600.0 seconds') expired on 2021-05-19T22:50:27+00:00
else:
    print(serialized_data == unsigned.decode())  # True
```

!!! tip
    The `ExpiredSignatureError` exception contains the signature timestamp as an aware datetime object (in UTC) in case you need that information to display something meaningful to the user.

### Choosing when to check the timestamp

!!! info "New in v2.4.0"

Sometimes it can be useful to make certain data expire, but there are situations that requires us to get that data as if it would never expire.

!!! success inline end "Signatures are always checked"

Since v2.4.0, `Blake2TimestampSigner` can omit the timestamp check when needed, acting like both a timestamped and a regular signer.  
This can be done in both `unsign` and `unsign_parts` methods.

```python
"""Choosing when to check the timestamp."""

from blake2signer import Blake2TimestampSigner

secret = 'todo está guardado en la memoria'
data = b'espina de la vida y de la historia'

signer = Blake2TimestampSigner(secret)

signed = signer.sign(data)
unsigned = signer.unsign(signed, max_age=None)  # Omits checking the timestamp

print(data == unsigned)  # True
```

## Using personalisation

The [personalisation parameter](details.md#about-salt-and-personalisation) is very important and prevents [mixing the signers](details.md#mixing-signers). It is referred in other packages as salt, and helps to defeat the abuse of using a signed stream for different signers that share the same key by changing the digest computation result.

!!! info "This can be done in every signer"

```python
"""Signing with personalisation."""

from blake2signer import Blake2SerializerSigner
from blake2signer import errors

secret = b'ZnVja3RoZXBvbGljZQ'
data = {
    'username': 'hackan',
    'id': 1,
    'is_admin': True,
}

cookie_signer = Blake2SerializerSigner(
    secret,
    personalisation=b'my-cookie-signer',
)
signed = cookie_signer.dumps(data)

upgs_signer = Blake2SerializerSigner(
    secret,
    personalisation=b'commercial upgrades signer',
)
try:
    upgs_signer.loads(signed)  # Signed with same secret and signer class, but...
except errors.InvalidSignatureError as exc:
    print(repr(exc))  # InvalidSignatureError('signature is not valid')
# Using the `personalisation` parameter made the sig to fail, thus protecting
# signed data to be loaded incorrectly.
```

!!! tip "Always use personalisation"
    You can set the personalisation parameter in every signer, and it is a good idea to always do it.

## Splitting signatures

!!! info "New in v2.0.0"

There are some situations were you need to transmit data and signature through different transports, such as different cookies (i.e. to store the signature in a HTTPOnly cookie and the data in a JS readable one) or different fields (i.e. to present data to the user but hide the signature because it is not pretty to read). For those situations a mechanism is provided out-of-the-box: `sign_parts`/`unsign_parts` and `dumps_parts`/`loads_parts`.

!!! info "This can be done in every signer"

```python
"""Splitting signatures."""

from blake2signer import Blake2SerializerSigner
from blake2signer import Blake2Signer

secret = 'Dónde está, dónde está'
data = 'Tehuel de la Torre'

# Blake2Signer and Blake2TimestampSigner provides `sign_parts` and
# `unsign_parts`
signer = Blake2Signer(secret)
signature = signer.sign_parts(data)
print(signature)  # Blake2Signature(signature=b'...', data=b'Tehuel de la Torre')
unsigned = signer.unsign_parts(signature)
print(data.encode() == unsigned)  # True

# Blake2SerializerSigner has the equivalent methods `dumps_parts` and
# `loads_parts` instead
signer = Blake2SerializerSigner(secret)
signature = signer.dumps_parts(data)
print(signature)  # Blake2SignatureDump(signature='...', data='IlRlaHVlbCBkZSBsYSBUb3JyZSI')
unsigned = signer.loads_parts(signature)
print(data == unsigned)  # True
```

!!! note
    Signature containers `Blake2Signature` and `Blake2SignatureDump` are equivalent, but the first one contains only bytes whereas the second one, only strings.

## Generating deterministic signatures

!!! info "New in v1.2.0"

By default, signatures are non-deterministic, but it is possible to generate deterministic ones (meaning, without salt) using the `deterministic` option when instantiating any signer. Read more about [deterministic signatures](details.md#about-salt-and-personalisation) in its section.

!!! info "This can be done in every signer"

```python
"""Generating deterministic signatures (the same goes for every signer!)."""

from blake2signer import Blake2Signer

secret = 'ZnVja3RoZXBvbGljZQ'
data = b'facundo castro presente'

signer = Blake2Signer(secret, deterministic=True)
signed = signer.sign(data)
print(len(signed))  # 46
# Shorter sig obtained as a consequence of not having salt
signed2 = signer.sign(data)
print(signed == signed2)  # True  # The signatures are equal

unsigned = signer.unsign(signed)
print(data == unsigned)  # True
```

## Rotating the secret

!!! info "New in v2.3.0"

Secrets can be rotated by an external mechanism, and passed to a signer as a sequence through the `secret` parameter. Read more about [rotating secrets](details.md#secret-rotation) in its section. 

!!! info "This can be done in every signer"

```python
"""Rotating the secret."""

from blake2signer import Blake2Signer, errors

secrets = [b'justicia' * 3, 'eXV0YSBhc2VzaW5hLCBubyBlcyBzb2xvIHVubyEhIQ']
data = 'lucas gonzález presente'

signer = Blake2Signer(secrets)
signed = signer.sign(data)  # Signed with the latest, newest, secret

# Let's rotate and add a new secret
secrets.append('QmFzdGEgZGUgZ2F0aWxsbyBmw6FjaWw')
signer = Blake2Signer(secrets)

# Previously signed data is still valid
unsigned = signer.unsign(signed)
print(data == unsigned.decode())  # True

# Once the old secret is rotated, old signatures won't be valid anymore
secrets = secrets[-1:]
signer = Blake2Signer(secrets)
try:
    signer.unsign(signed)
except errors.InvalidSignatureError as exc:
    print(exc)  # signature is not valid

# New signatures are made with the newest secret
secrets.append(b'no tolerance to injustice :)')
signed = Blake2Signer(secrets).sign(data)
unsigned = Blake2Signer(secrets[-1]).unsign(signed)
print(data == unsigned.decode())  # True
```

## Changing the hasher

You can use either `blake2b` or `blake2s`: the first one is optimized for 64b platforms, and the second, for 8-32b platforms (read more about them in their [official site](https://blake2.net/)).

!!! info "This can be done in every signer"

```python
"""Signing with another hasher (the same goes for every signer!)."""

from blake2signer import Blake2SerializerSigner

secret = b'ZnVja3RoZXBvbGljZQ'
data = {
    'username': 'hackan',
    'id': 1,
    'is_admin': True,
}

signer = Blake2SerializerSigner(
    secret,
    hasher=Blake2SerializerSigner.Hashers.blake2s,
)
signed = signer.dumps(data)
print(signed)

unsigned = signer.loads(signed)
print(data == unsigned)  # True
```

!!! tip "Changing the hasher"
    All signers have the attribute `Hashers` to use in the selection of a hasher, or you can use strings directly:

    * `Blake2SerializerSigner(secret, hasher=Blake2SerializerSigner.Hashers.blake2s)`
    * `Blake2SerializerSigner(secret, hasher='blake2s')`

### Using BLAKE3

!!! info "New in v2.2.0"

You can use BLAKE3 if you have the [`blake3`](https://pypi.org/project/blake3/) package installed. Check the [comparison against BLAKE2](performance.md#blake-versions).

!!! info "This can be done in every signer"

```python
"""Signing with BLAKE3 (the same goes for every signer!)."""

from blake2signer import Blake2Signer

secret = b'civil disobedience is necessary'
data = b'remember Aaron Swartz'

signer = Blake2Signer(
    secret,
    hasher=Blake2Signer.Hashers.blake3,  # 'blake3'
)
signed = signer.sign(data)
print(signed)

unsigned = signer.unsign(signed)
print(data == unsigned)  # True
```

## Changing the encoder

There are three [encoders provided by this package](details.md#encoders-serializers-and-compressors): a Base64 URL safe encoder (default), a Base 32 encoder and a Base 16/Hex encoder.

!!! info "This can be done in every signer since v2.0.0"

```python
"""Changing the encoder."""

from blake2signer import Blake2SerializerSigner
from blake2signer import Blake2Signer
from blake2signer import Blake2TimestampSigner
from blake2signer.encoders import B32Encoder
from blake2signer.encoders import B64URLEncoder
from blake2signer.encoders import HexEncoder

secret = b'may the force be with you'
data = 'always'

signer1 = Blake2SerializerSigner(secret, encoder=B64URLEncoder)  # Default
signed = signer1.dumps(data)
print(signed)  # The signature and payload have only base 64 url safe chars
unsigned = signer1.loads(signed)
print(data == unsigned)  # True

signer2 = Blake2Signer(secret, encoder=B32Encoder)
signed = signer2.sign(data)
print(signed)  # The signature only has base 32 chars
unsigned = signer2.unsign(signed)
print(data == unsigned.decode())  # True

signer3 = Blake2TimestampSigner(secret, encoder=HexEncoder)
signed = signer3.sign(data)
print(signed)  # The signature only has hex chars
unsigned = signer3.unsign(signed, max_age=5)
print(data == unsigned.decode())  # True

# Mixing the signers is protected as always
signer1.loads(signed)
# blake2signer.errors.InvalidSignatureError: signature is not valid
signer2.unsign(signed)
# blake2signer.errors.InvalidSignatureError: signature is not valid
```

!!! tip "Custom encoder"
    You can [create a custom encoder](#using-a-custom-encoder).

## Using a custom encoder

If you need to use an encoder that is not implemented by this package, such as A85 or UUencode, you can do so: all you need to do is implement the `EncoderInterface`, and define how is your encoder encoding and decoding, as well as indicating its alphabet. That's it.

!!! note
    The separator and compression flag characters must not belong to the encoder alphabet. This is to correctly split the signature and payload before decoding (it would be dangerous to do it the other way around), and to unequivocally identify a compressed payload, respectively.

```python
"""Sample of custom encoder."""

import base64
import typing

from blake2signer import Blake2SerializerSigner
from blake2signer.interfaces import EncoderInterface
from blake2signer.utils import force_bytes


class Ascii85Encoder(EncoderInterface):
    """Ascii85 encoder."""

    @property
    def alphabet(self) -> bytes:
        return b''.join(bytes((i,)) for i in range(33, 118))

    def encode(self, data: typing.AnyStr) -> bytes:
        return base64.a85encode(force_bytes(data))

    def decode(self, data: typing.AnyStr) -> bytes:
        return base64.a85decode(force_bytes(data))


secret = b'TRIPS waiver please!'
data = {'wish': 'vaccines'}

signer = Blake2SerializerSigner(secret, encoder=Ascii85Encoder, separator=b'y')
signed = signer.dumps(data)
print(signed)  # ...yHQmZJF(caY,'IC)@qfglF!?#

unsigned = signer.loads(signed)
print(unsigned)  # {'wish': 'vaccines'}
print(data == unsigned)  # True
```

## Changing the separator character

If you are limited to a certain character range in your signed data transport, you can set the separator character to any value needed (as well as [the encoder](#changing-the-encoder) and the [compression flag](#changing-the-compression-flag)). The only limitation is that the character can't belong to the encoder alphabet. This is because the separator character is used to separate the signature, the timestamp if any, and the data payload.

!!! info
    It defaults to a dot (`.`).

!!! info "This can be done in every signer"

```python
"""Changing the separator character."""

from blake2signer import Blake2Signer

secret = 'there is no knowledge that is no power'
data = b'42'

signer = Blake2Signer(secret, separator=':')

signed = signer.sign(data)
print(signed)  # ...:42
print(data == signer.unsign(signed))  # True
```

!!! note
    For versions older than v2, the *separator* can be set through the class attribute `SEPARATOR`. Note that this change affects all instances of the class, which is why said value was refactored to be an instance attribute.

## Changing the digest size

One advantage of BLAKE2+ is that it is very flexible and tweakable, and one of the things we can tweak is its digest size. This means that the output size of the signer can be changed for shorter or longer signatures: longer ones are more secure given that they are almost impossible to bruteforce. It is set to 16 bytes by default, which is a good compromise between security and length.

!!! note
    A minimum size of 16 bytes is enforced, but [it can be changed](#changing-the-digest-size-limit).

!!! info "This can be done in every signer"

```python
"""Changing the digest size."""

from blake2signer import Blake2Signer

secret = b'Han shot first!!'
data = b''

signer = Blake2Signer(secret, digest_size=64)  # Size in bytes
signed = signer.sign(data)
print(len(signed))  # 103: 16 for salt, 86 for the encoded 64B digest, 1 for the separator
```

!!! note
    The maximum digest size depends on the hasher: 64 bytes for *blake2b*, and 32 for *blake2s* (check the [Python docs](https://docs.python.org/3/library/hashlib.html#creating-hash-objects) for more info).

### Changing the digest size limit

There can be some situations where signature length is crucial, and thus some security margin needs to be sacrificed. It is possible to override the minimum enforced value, although you need to consider its implications. You can increase the minimum, too! Bear in mind that the maximums depends on the hasher, so you shouldn't set it higher than 32.  
To change the limit, set the class attribute `MIN_DIGEST_SIZE` to the desired value in bytes.

!!! danger
    Reducing the digest size lower than 8 bytes (128 bits) poses an increasing security risk.

!!! info "This can be done in every signer"

```python
"""Changing the digest size limit."""

from blake2signer import Blake2Signer

secret = b'Han shot first!!'
data = b''
Blake2Signer.MIN_DIGEST_SIZE = 8  # Size in bytes

signer = Blake2Signer(secret, digest_size=8)
signed = signer.sign(data)
print(len(signed))  # 28: 16 for salt, 11 for the encoded 8B digest, 1 for the separator

signer = Blake2Signer(secret, digest_size=8, deterministic=True)
signed = signer.sign(data)
print(len(signed))  # 12: 11 for the encoded 8B digest, 1 for the separator
```

!!! warning
    All instances of the signer are affected by the class attribute change.

## Creating a custom SerializerSigner class

You can create your own *SerializerSigner* using provided `Blake2SerializerSignerBase` and any of the mixins: `SerializerMixin` or `CompressorMixin` (`EncoderMixin` is included in the base class) or even creating your own mixin inheriting from `Mixin` (note that the class inheritance order matters, and the mixins must come first leaving the chosen base class last).

!!! danger
    This is rather advanced, and you should think if this is what you really need to do.

```python
"""Custom encoder compressor signer class example."""

import typing

from blake2signer.bases import Blake2SerializerSignerBase
from blake2signer.mixins import CompressorMixin


class MyEncoderCompressorSigner(CompressorMixin, Blake2SerializerSignerBase):

    def _dumps(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        data_bytes = self._force_bytes(data)

        compressed, is_compressed = self._compress(data_bytes)

        encoded = self._encode(compressed)

        if is_compressed:
            encoded = self._add_compression_flag(encoded)

        return encoded

    def _loads(self, dumped_data: bytes, **kwargs: typing.Any) -> typing.Any:
        data, is_compressed = self._remove_compression_flag_if_compressed(dumped_data)

        decoded = self._decode(data)

        return self._decompress(decoded) if is_compressed else decoded

    def dumps(self, data: typing.AnyStr) -> str:
        dump = self._dumps(data)

        return self._compose(dump, signature=self._proper_sign(dump)).decode()

    def loads(self, signed_data: typing.AnyStr) -> bytes:
        parts = self._decompose(self._force_bytes(signed_data))

        return self._loads(self._proper_unsign(parts))


secret = b'super-secret-value'
signer = MyEncoderCompressorSigner(secret)
data = b'acab' * 100
signed = signer.dumps(data)
print(len(signed) < len(data))  # True
print(signed)  # .....eJxLTE5MShzFgwYDAKeVmL0
print(signer.loads(signed) == data)  # True
```

```python
"""Custom SerializerSigner class example."""

import typing

from blake2signer.bases import Blake2SerializerSignerBase


class MySerializerSigner(Blake2SerializerSignerBase):  # Contains encoder mixin

    def _dumps(self, data: typing.Any, **kwargs: typing.Any) -> bytes:
        return self._encode(self._force_bytes(data))

    def _loads(self, dumped_data: bytes, **kwargs: typing.Any) -> typing.Any:
        return self._decode(dumped_data).decode()

    def dumps(self, data: typing.Any) -> str:
        dump = self._dumps(data)

        return self._compose(dump, signature=self._proper_sign(dump)).decode()

    def loads(self, signed_data: typing.AnyStr) -> typing.Any:
        parts = self._decompose(self._force_bytes(signed_data))

        return self._loads(self._proper_unsign(parts))


secret = b'super-secret-value'
signer = MySerializerSigner(secret)
data = 'memoria y justicia'
signed = signer.dumps(data)
print(signed)  # ....bWVtb3JpYSB5IGp1c3RpY2lh
print(signer.loads(signed) == data)  # True
```
