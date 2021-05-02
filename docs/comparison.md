# Comparison

Comparison against other similar libraries.

## It's Dangerous

[![It's Dangerous Logo](https://itsdangerous.palletsprojects.com/en/1.1.x/_images/itsdangerous-logo.png)](https://itsdangerous.palletsprojects.com/)

### Signing interface

Both `itsdangerous.Signer` and `itsdangerous.TimestampSigner` appends the signature to the given string, whereas `blake2signer.Blake2Signer` and `blake2signer.Blake2TimestampSigner` prepends it (with salt). Other than that, this package can be a drop-in replacement and vice versa.

=== "ItsDangerous"

    ```python
    from itsdangerous import SignatureExpired
    from itsdangerous import Signer
    from itsdangerous import TimestampSigner

    # Signer
    signer = Signer('secret-key')
    print(signer.sign('my string'))
    print(signer.unsign(b'my string.wh6tMHxLgJqB6oY1uT73iMlyrOA'))  # b'my string'

    # Timestamp signer
    signer = TimestampSigner('secret-key')
    print(signer.sign('foo'))
    try:
        print(signer.unsign(b'foo.YIZMkg.FQdIC8gFmkwy4w8KC05IQfzU-Gc', max_age=3600))  # b'foo'
    except SignatureExpired as exc:
        print(repr(exc))  # SignatureExpired: Signature age ... > 3600 seconds
    ```

=== "Blake2Signer"

    ```python
    from blake2signer import Blake2Signer
    from blake2signer import Blake2TimestampSigner
    from blake2signer.errors import ExpiredSignatureError

    # Signer
    signer = Blake2Signer('super-secret-key')  # 16 bytes min size enforced
    print(signer.sign('my string'))
    print(signer.unsign(b'tUt_Nu7h86uvsUyQDRIm6d3T-cKlSUlt--JR_w.my string'))  # b'my string'

    # Timestamp signer
    signer = Blake2TimestampSigner('super-secret-key')
    print(signer.sign('foo'))
    try:
        print(signer.unsign(b'tUY3jX-uu4Luqaya0Yr0WgvHIaSboPiP-YwBAw.YIbw6w.foo', max_age=3600))  # b'foo'
    except ExpiredSignatureError as exc:
        print(repr(exc))  # ExpiredSignatureError('signature has expired, age ... > 3600.0 seconds')
    ```

!!! abstract "Main differences"
    * *itsdangerous* uses *sha-1* by default as hashing backend, this package uses *blake2b*.
    * *itsdangerous* creates deterministic signatures by default, this package doesn't (see the [example on generating deterministic signatures](examples.md#generating-deterministic-signatures)).
    * *itsdangerous* appends signature (and timestamp) to data, this package prepends it.

### Serializing interface

For serializing and signing objects, *itsdangerous* provides four classes: `Serializer`, `URLSafeSerializer`, `TimedSerializer` and `URLSafeTimedSerializer`. This package provides similar capabilities in a single class: `Blake2SerializerSigner`.  
The interfaces are similar and can be used as drop-in replacements.

=== "ItsDangerous"

    ```python
    from itsdangerous import SignatureExpired
    from itsdangerous.serializer import Serializer
    from itsdangerous.timed import TimedSerializer
    from itsdangerous.url_safe import URLSafeSerializer
    from itsdangerous.url_safe import URLSafeTimedSerializer

    # Serializer signer
    signer = Serializer('secret-key')
    print(signer.dumps([1, 2, 3, 4]))
    print(signer.loads('[1, 2, 3, 4].r7R9RhGgDPvvWl3iNzLuIIfELmo'))  # [1, 2, 3, 4]

    # Timestamp serializer signer
    signer = TimedSerializer('secret-key')
    print(signer.dumps([1, 2, 3, 4]))
    try:
        print(signer.loads('[1, 2, 3, 4].YIZQ-w.0wubnZ3HhtaKvWuo-Kpks7F9Pfs', max_age=3600))  # [1, 2, 3, 4]
    except SignatureExpired as exc:
        print(repr(exc))  # SignatureExpired: Signature age ... > 3600 seconds

    # Encoder serializer signer
    signer = URLSafeSerializer('secret-key')
    print(signer.dumps([1, 2, 3, 4]))
    print(signer.loads('WzEsMiwzLDRd.wSPHqC0gR7VUqivlSukJ0IeTDgo'))  # [1, 2, 3, 4]

    # Timestamp encoder serializer signer
    signer = URLSafeTimedSerializer('secret-key')
    print(signer.dumps([1, 2, 3, 4]))
    try:
        print(signer.loads('WzEsMiwzLDRd.YIZRkQ.1Q_nKsgoxD_JtddAyWxBBnmR87M', max_age=3600))  # [1, 2, 3, 4]
    except SignatureExpired as exc:
        print(repr(exc))  # SignatureExpired: Signature age ... > 3600 seconds
    ```

=== "Blake2Signer"

    ```python
    from blake2signer import Blake2SerializerSigner
    from blake2signer.errors import ExpiredSignatureError

    # Encoder compressor serializer signer
    signer = Blake2SerializerSigner('super-secret-key')  # 16 bytes min size enforced
    print(signer.dumps([1, 2, 3, 4]))
    print(signer.loads('0i5Gvawg0724DBwXAG8rsUegCgCL-VLhjfOQ2g.WzEsMiwzLDRd'))  # [1, 2, 3, 4]

    # Timestamp encoder compressor serializer signer
    signer = Blake2SerializerSigner('super-secret-key', max_age=3600)  # With timestamp
    print(signer.dumps([1, 2, 3, 4]))
    try:
        print(signer.loads('_zhFEz1fpIaTiUd6lk8M1u_5Q0ChEx671Mux1Q.YIcL8w.WzEsMiwzLDRd'))  # [1, 2, 3, 4]
    except ExpiredSignatureError as exc:
        print(repr(exc))  # ExpiredSignatureError('signature has expired, age ... > 3600.0 seconds')
    ```

!!! abstract "Main differences"
    * *itsdangerous* provides four different serializers to handle different cases, this package provides just one.
    * *itsdangerous* can serialize without encoding data, this package can't (not directly, see the [example on how to serialize without encoding](examples.md#using-non-serializer-signers)).
    * *itsdangerous* can't easily change the encoder, compressor and/or serializer, this package can.
    * *itsdangerous* provides an interface to load data unsafely, this package doesn't (and probably never will).

## Django's signer

[![Django's Logo](https://static.djangoproject.com/img/logos/django-logo-negative.png)](https://docs.djangoproject.com)

### Signing interface

The `django.core.signing.Signer` appends the signature to the given string, whereas `blake2signer.Blake2Signer` prepends it (with salt). Other than that, this package can be a drop-in replacement and vice versa.

=== "Django"

    ```python
    from django.conf import settings
    from django.core.signing import SignatureExpired
    from django.core.signing import Signer
    from django.core.signing import TimestampSigner

    settings.configure()  # Initialize Django

    # Signer
    signer = Signer('secret-key')
    print(signer.sign('My string'))
    print(signer.unsign('My string:ZMytWkz1GTS_Nk71RrVV19aB0pjYncBU3hgXOh78xk8'))  # My string

    # Timestamp signer
    signer = TimestampSigner('secret-key')
    print(signer.sign('My string'))
    try:
        print(signer.unsign('My string:1lb46Q:WXYzPtY3ICSPVSU4qqGXfJ2_UiuiOfQV4S47-q6eT70', max_age=3600))  # My string
    except SignatureExpired as exc:
        print(repr(exc))  # SignatureExpired: Signature age ... > 3600 seconds
    ```

=== "Blake2Signer"

    ```python
    from blake2signer import Blake2Signer
    from blake2signer import Blake2TimestampSigner
    from blake2signer.errors import ExpiredSignatureError

    # Signer
    signer = Blake2Signer('super-secret-key')  # 16 bytes min size enforced
    print(signer.sign('My string'))
    print(signer.unsign(b'RjlBYraVdIvRuH8uYpVO3kBp4qfkt93r2EaqMQ.My string'))  # b'my string'

    # Timestamp signer
    signer = Blake2TimestampSigner('super-secret-key')
    print(signer.sign('My string'))
    try:
        print(signer.unsign(b'O8W1aRlq6_RqkDsB3FYKNXu0Tzu9ziNKWr3xDA.YI8YXQ.My string', max_age=3600))  # b'foo'
    except ExpiredSignatureError as exc:
        print(repr(exc))  # ExpiredSignatureError('signature has expired, age ... > 3600.0 seconds')
    ```

!!! abstract "Main differences"
    * *django* uses *sha-256* by default as hashing backend, this package uses *blake2b*.
    * *django* creates deterministic signatures by default, this package doesn't.
    * *django* appends signature (and timestamp) to data, this package prepends it.
    * *django* uses the character `:` as separator by default, this package uses `.`.

### Serializing interface

For serializing and signing objects, *Django* provides two functions: `dumps` and `loads`. This package provides similar capabilities in a single class: `Blake2SerializerSigner`.  
The interfaces are similar and can be used as drop-in replacements.

=== "Django"

    ```python
    from django.conf import settings
    from django.core import signing
    from django.core.signing import SignatureExpired

    settings.configure()  # Initialize Django

    # Encoder compressor serializer signer
    print(signing.dumps({'foo': 'bar'}, key='secret-key'))
    print(signing.loads('eyJmb28iOiJiYXIifQ:1lb4Iy:GvulJZFUKKn60lWG8WoAYfs4SY-Ctdm-PVkApi44nlE', key='secret-key'))  # {'foo': 'bar'}

    # Timestamp encoder compressor serializer signer
    try:
        print(signing.loads('eyJmb28iOiJiYXIifQ:1lb4Iy:GvulJZFUKKn60lWG8WoAYfs4SY-Ctdm-PVkApi44nlE', key='secret-key', max_age=3600))  # {'foo': 'bar'}
    except SignatureExpired as exc:
        print(repr(exc))  # SignatureExpired: Signature age ... > 3600 seconds
    ```

=== "Blake2Signer"

    ```python
    from blake2signer import Blake2SerializerSigner
    from blake2signer.errors import ExpiredSignatureError

    # Encoder compressor serializer signer
    signer = Blake2SerializerSigner('super-secret-key')  # 16 bytes min size enforced
    print(signer.dumps({'foo': 'bar'}))
    print(signer.loads('Is7yyhMWydBGzqvIpynb_sEqudc6AcAYnItCow.eyJmb28iOiJiYXIifQ'))  # {'foo': 'bar'}

    # Timestamp encoder compressor serializer signer
    signer = Blake2SerializerSigner('super-secret-key', max_age=3600)  # With timestamp
    print(signer.dumps({'foo': 'bar'}))
    try:
        print(signer.loads('7nKxO-QcE60ciWiwu5OHrQz3ftKgIhh92B3pgQ.YJYbrA.eyJmb28iOiJiYXIifQ'))  # {'foo': 'bar'}
    except ExpiredSignatureError as exc:
        print(repr(exc))  # ExpiredSignatureError('signature has expired, age ... > 3600.0 seconds')
    ```

!!! abstract "Main differences"
    * *Django* provides two functions to handle different cases, this package provides just one class.
    * *Django* can't easily change the encoder, compressor and/or serializer, this package can.
    * *Django* doesn't compress by default, this package does (and [*smartly*](examples.md#compressing-data): it won't compress if it turns out detrimental).

## PyJWT

![JWT Logo](https://jwt.io/img/logo-asset.svg)

### Serializing interface

*PyJWT* implements [RFC 7519](https://tools.ietf.org/html/rfc7519) for JSON Web Token which is quite complex, not needed in most cases and can easily turn into a *footgun*; this package is uncomplicated and can be used instead on most situations. On the other hand, for a similar utility but without [the many design deficits that plague JWT](https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid), see [PASETO](https://paseto.io/).

=== "PyJWT"

    ```python
    import jwt

    print(jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256'))
    print(jwt.decode(
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lIjoicGF5bG9hZCJ9.Joh1R2dYzkRvDkqv3sygm5YyK8Gi4ShZqbhK2gxcs2U',
        'secret',
        algorithms=['HS256'],
    ))  # {'some': 'payload'}
    ```

=== "Blake2Signer"

    ```python
    from blake2signer import Blake2SerializerSigner

    signer = Blake2SerializerSigner('super-secret-key')  # 16 bytes min size enforced
    print(signer.dumps({'some': 'payload'})
    print(signer.loads('xJigCzDl2Naq3pt8dHNEZDY7ZIYLZ24U-No83g.eyJzb21lIjoicGF5bG9hZCJ9'))  # {'some': 'payload'}

    ```

!!! abstract "Main differences"
    * *PyJWT* can handle different algorithms dynamically - using a data header -, this package can't and never will.
    * *PyJWT* can't change the encoder or serializer, this package can.
    * *PyJWT* can't compress data, this package does (and [*smartly*](examples.md#compressing-data): it won't compress if it turns out detrimental).

## Performance comparison

Following is the performance comparison of this lib against [It's Dangerous](https://itsdangerous.palletsprojects.com/en/1.1.x), [Django](https://www.djangoproject.com) and [PyJWT](https://pyjwt.readthedocs.io). Generally speaking, it is as fast or a bit faster than the other libs, so you should choose one or the other based on usability and fitting-your-needs rather than performance.

!!! info
    Take into account that the only significant performance comparison exists when blake2b or blake2s is used as hashing algorithm, otherwise the algorithm performance may outweigh the implementation. Other algorithms are noted here to be taken into consideration against the BLAKE2 algorithm and not against this library in particular.  
    A reference function that uses blake2b directly is used to compare against it: this lib can't be faster than that.

Regarding **itsdangerous** (1.1.0), I found this lib to be *marginally faster* when compared to it using blake2b, *somewhat faster* regarding sha256, 384 and 512 and *slower* regarding sha1.

Regarding **django** (3.2.1), I found this lib to be *quite faster* when compared to it using blake2b, sha256, sha384 and sha512 and *slower* regarding sha1. Note that its Signer doesn't handle arbitrary bytes well (it breaks raising `BadSignature` if you use `data_b` below, so it needs `data_s`).

Regarding **pyjwt** (2.1.0), I found this lib to be *quite faster* when compared to it using blake2b (hack) and sha256 (hs256).

!!! note
    The standard deviation presented on each evaluation should be at least two orders of magnitude lower than the mean for appropriate results. As a simple reference, for an Intel i7-6820HQ @ 2.70GHz × 8 with 16 GB memory the mean is in `ms` and the std dev should be in `us`.

```python
"""Timing comparison."""

import json
from hashlib import blake2b
from hashlib import blake2s
from hashlib import sha1
from hashlib import sha256
from hashlib import sha384
from hashlib import sha512
from hmac import compare_digest
from secrets import token_bytes

import jwt
from django.conf import settings
from django.core import signing
from itsdangerous import Signer
from itsdangerous import URLSafeSerializer

from blake2signer import Blake2SerializerSigner
from blake2signer import Blake2Signer


def format_time(
        dt: float,
        *,
        unit: str = None,
        precision: int = 3,
) -> str:
    """Format time (copied from timeit lib)."""
    units = {'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0}

    if unit:
        scale = units[unit]
    else:
        scales = [(scale, unit) for unit, scale in units.items()]
        scales.sort(reverse=True)
        for scale, unit in scales:
            if dt >= scale:
                break

    return '%.*g %s' % (precision, dt / scale, unit)

def print_row(name: str, value: float, ok: bool, baseline: float):
    """Print a table row."""
    rel = int(value * 100 / baseline) - 100
    perf_diff = '' if rel == 0 else ('(slower than baseline)' if rel > 0 else '(faster than baseline)')
    print(
        name.ljust(40),
        '|',
        format_time(value).rjust(13),
        '|',
        ('√' if ok else '⚠').center(7),
        '|',
        f'{rel}%'.rjust(4) if value != baseline else 'baseline',
        perf_diff,
    )


# Hack to get PyJWT with blake2b
jwt_b2 = jwt.PyJWS()
jwt_b2._algorithms.update({
    'HSB2B': jwt.algorithms.HMACAlgorithm(blake2b),
    'HSB2S': jwt.algorithms.HMACAlgorithm(blake2s),
})


def jwt_b2_encode(
        payload: dict,
        key: str,
        algo: str,
) -> str:
    """Hack the JWT encode method."""
    # https://github.com/jpadilla/pyjwt/blob/69d1e8b5f450f2b1df42149d977b48e286df1054/jwt/api_jwt.py#L37
    # Payload
    payload = payload.copy()
    for time_claim in ['exp', 'iat', 'nbf']:
        if payload.get(time_claim):
            pass

    json_payload = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    return jwt_b2.encode(json_payload, key, algo)


def jwt_b2_decode(
        jwt: str,
        key: str,
        algorithms: list = None,
        options: dict = None,
        **kwargs,
):
    """Hack the JWT decode method."""
    # https://github.com/jpadilla/pyjwt/blob/69d1e8b5f450f2b1df42149d977b48e286df1054/jwt/api_jwt.py#L65
    options = {'verify_signature': True}

    if not options['verify_signature']:
        options.setdefault('verify_exp', False)
        options.setdefault('verify_nbf', False)
        options.setdefault('verify_iat', False)
        options.setdefault('verify_aud', False)
        options.setdefault('verify_iss', False)

    if options['verify_signature'] and not algorithms:
        raise ValueError(
            'It is required that you pass in a value for the "algorithms" argument when calling decode().'
        )

    decoded = jwt_b2.decode_complete(
        jwt,
        key=key,
        algorithms=algorithms,
        options=options,
        **kwargs,
    )

    try:
        payload = json.loads(decoded["payload"])
    except ValueError as e:
        raise ValueError("Invalid payload string: %s" % e)
    if not isinstance(payload, dict):
        raise ValueError("Invalid payload string: must be a json object")

    return payload


def blake2b_sign(value: bytes, key: bytes) -> bytes:
    """A basic "singing" function using blake2b to be used as sentinel."""
    salt = token_bytes(blake2b.SALT_SIZE)
    sig = blake2b(value, key=key, salt=salt, digest_size=16).digest()

    return salt + sig + b'.' + value


def blake2b_unsign(signed_data: bytes, key: bytes) -> bytes:
    """A basic "unsinging" function using blake2b to be used as sentinel."""
    salt = signed_data[:blake2b.SALT_SIZE]
    sig = signed_data[blake2b.SALT_SIZE:blake2b.SALT_SIZE + 16]
    value = signed_data[blake2b.SALT_SIZE + 16 + 1:]

    good_sig = blake2b(value, key=key, salt=salt, digest_size=16).digest()

    if compare_digest(good_sig, sig):
        return value

    raise ValueError('signature mismatch')


def blake2s_sign(value: bytes, key: bytes) -> bytes:
    """A basic "singing" function using blake2s to be used as sentinel."""
    salt = token_bytes(blake2s.SALT_SIZE)
    sig = blake2s(value, key=key, salt=salt, digest_size=16).digest()

    return salt + sig + b'.' + value


def blake2s_unsign(signed_data: bytes, key: bytes) -> bytes:
    """A basic "unsinging" function using blake2s to be used as sentinel."""
    salt = signed_data[:blake2s.SALT_SIZE]
    sig = signed_data[blake2s.SALT_SIZE:blake2s.SALT_SIZE + 16]
    value = signed_data[blake2s.SALT_SIZE + 16 + 1:]

    good_sig = blake2s(value, key=key, salt=salt, digest_size=16).digest()

    if compare_digest(good_sig, sig):
        return value

    raise ValueError('signature mismatch')


settings.configure()  # Initialize Django

secret = b'1' * 16

blake2signer = Blake2Signer(secret)
blake2signer_b2s = Blake2Signer(secret, hasher='blake2s')
itdsigner_b2 = Signer(secret, digest_method=blake2b)
itdsigner_b2s = Signer(secret, digest_method=blake2s)
itdsigner_s1 = Signer(secret, digest_method=sha1)
itdsigner_s256 = Signer(secret, digest_method=sha256)
itdsigner_s384 = Signer(secret, digest_method=sha384)
itdsigner_s512 = Signer(secret, digest_method=sha512)
djsigner_b2 = signing.Signer(secret, algorithm='blake2b')
djsigner_b2s = signing.Signer(secret, algorithm='blake2s')
djsigner_s1 = signing.Signer(secret, algorithm='sha1')
djsigner_s256 = signing.Signer(secret, algorithm='sha256')
djsigner_s384 = signing.Signer(secret, algorithm='sha384')
djsigner_s512 = signing.Signer(secret, algorithm='sha512')
blake2serializer = Blake2SerializerSigner(secret)
blake2serializer_b2s = Blake2SerializerSigner(secret, hasher='blake2s')
itdserializer_b2 = URLSafeSerializer(secret, signer_kwargs={'digest_method': blake2b})
itdserializer_b2s = URLSafeSerializer(secret, signer_kwargs={'digest_method': blake2s})

# regular and big payloads
for data in ({'payload': [{'a': 'b'}, 1] * 6}, {'payload': [{'a': 'b'}, 1] * 1_000}):
    data_s = json.dumps(data)
    data_b = data_s.encode()
    print('Payload size ~:', len(data_b), 'bytes')

    signers = {}
    serializers = {}

    print('Calculating, please wait (this will take a while)...')
    print()

    # Using ipython:
    print('Blake2Signer(blake2b)')
    signers['Blake2Signer(blake2b)'] = %timeit -o -r 10 blake2signer.unsign(blake2signer.sign(data_b))
    print()

    print('Blake2Signer(blake2s)')
    signers['Blake2Signer(blake2s)'] = %timeit -o -r 10 blake2signer_b2s.unsign(blake2signer_b2s.sign(data_b))
    print()

    print('Blake2b(sentinel)')
    signers['Blake2(sentinel)'] = %timeit -o -r 10 blake2b_unsign(blake2b_sign(data_b, secret), secret)
    print()

    print('Blake2s(sentinel)')
    signers['Blake2s(sentinel)'] = %timeit -o -r 10 blake2s_unsign(blake2s_sign(data_b, secret), secret)
    print()

    print('ItsDangerousSigner(blake2b)')
    signers['ItsDangerousSigner(blake2b)'] = %timeit -o -r 10 itdsigner_b2.unsign(itdsigner_b2.sign(data_b))
    print()

    print('ItsDangerousSigner(blake2s)')
    signers['ItsDangerousSigner(blake2s)'] = %timeit -o -r 10 itdsigner_b2s.unsign(itdsigner_b2s.sign(data_b))
    print()

    print('ItsDangerousSigner(sha1)')
    signers['ItsDangerousSigner(sha1)'] = %timeit -o -r 10 itdsigner_s1.unsign(itdsigner_s1.sign(data_b))
    print()

    print('ItsDangerousSigner(sha256)')
    signers['ItsDangerousSigner(sha256)'] = %timeit -o -r 10 itdsigner_s256.unsign(itdsigner_s256.sign(data_b))
    print()

    print('ItsDangerousSigner(sha384)')
    signers['ItsDangerousSigner(sha384)'] = %timeit -o -r 10 itdsigner_s384.unsign(itdsigner_s384.sign(data_b))
    print()

    print('ItsDangerousSigner(sha512)')
    signers['ItsDangerousSigner(sha512)'] = %timeit -o -r 10 itdsigner_s512.unsign(itdsigner_s512.sign(data_b))
    print()

    print('DjangoSigner(blake2b)')
    signers['DjangoSigner(blake2b)'] = %timeit -o -r 10 djsigner_b2.unsign(djsigner_b2.sign(data_s))
    print()

    print('DjangoSigner(blake2s)')
    signers['DjangoSigner(blake2s)'] = %timeit -o -r 10 djsigner_b2s.unsign(djsigner_b2s.sign(data_s))
    print()

    print('DjangoSigner(sha1)')
    signers['DjangoSigner(sha1)'] = %timeit -o -r 10 djsigner_s1.unsign(djsigner_s1.sign(data_s))
    print()

    print('DjangoSigner(sha256)')
    signers['DjangoSigner(sha256)'] = %timeit -o -r 10 djsigner_s256.unsign(djsigner_s256.sign(data_s))
    print()

    print('DjangoSigner(sha384)')
    signers['DjangoSigner(sha384)'] = %timeit -o -r 10 djsigner_s384.unsign(djsigner_s384.sign(data_s))
    print()

    print('DjangoSigner(sha512)')
    signers['DjangoSigner(sha512)'] = %timeit -o -r 10 djsigner_s512.unsign(djsigner_s512.sign(data_s))
    print()

    print('Blake2SerializerSigner(blake2b)')
    serializers['Blake2SerializerSigner(blake2b)'] = %timeit -o -r 10 blake2serializer.loads(blake2serializer.dumps(data))
    print()

    print('Blake2SerializerSigner(blake2s)')
    serializers['Blake2SerializerSigner(blake2s)'] = %timeit -o -r 10 blake2serializer_b2s.loads(blake2serializer_b2s.dumps(data))
    print()

    print('ItsDangerousURLSafeSerializer(blake2b)')
    serializers['ItsDangerousURLSafeSerializer(blake2b)'] = %timeit -o -r 10 itdserializer_b2.loads(itdserializer_b2.dumps(data))
    print()

    print('ItsDangerousURLSafeSerializer(blake2s)')
    serializers['ItsDangerousURLSafeSerializer(blake2s)'] = %timeit -o -r 10 itdserializer_b2s.loads(itdserializer_b2s.dumps(data))
    print()

    print('DjangoSerializer(sha256)')
    serializers['DjangoSerializer(sha256)'] = %timeit -o -r 10 signing.loads(signing.dumps(data, key=secret, compress=True), key=secret)
    print()

    print('PyJWTSerializer(sha256)')
    serializers['PyJWTSerializer(sha256)'] = %timeit -o -r 10 jwt.decode(jwt.encode(data, secret, algorithm='HS256'), secret, algorithms=['HS256'])
    print()

    print('PyJWTSerializer(blake2b)')
    serializers['PyJWTSerializer(blake2b)'] = %timeit -o -r 10 jwt_b2_decode(jwt_b2_encode(data, secret, 'HSB2B'), secret, algorithms=['HSB2B'])
    print()

    print('PyJWTSerializer(blake2s)')
    serializers['PyJWTSerializer(blake2s)'] = %timeit -o -r 10 jwt_b2_decode(jwt_b2_encode(data, secret, 'HSB2S'), secret, algorithms=['HSB2S'])
    print()

    print('Signer'.ljust(40), '| Best Abs Time | Measure | Comparison')
    print('-' * 40, '|', '-' * 13, '|', '-' * 7, '|', '-' * 27)
    baseline = signers['Blake2Signer(blake2b)'].best
    for timing in signers:
        ok = (signers[timing].best / signers[timing].stdev) > 60
        print_row(timing, signers[timing].best, ok, baseline)

    print()
    print('Serializer'.ljust(40), '| Best Abs Time | Measure | Comparison')
    print('-' * 40, '|', '-' * 13, '|', '-' * 7, '|', '-' * 27)
    baseline = serializers['Blake2SerializerSigner(blake2b)'].best
    for timing in serializers:
        ok = (serializers[timing].best / serializers[timing].stdev) > 60
        print_row(timing, serializers[timing].best, ok, baseline)

    print()
```
