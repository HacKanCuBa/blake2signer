# Details

Some details and general information about the signers in this lib.

## Signers

This module provides three signer classes:

* [**Blake2SerializerSigner**](signers.md#blake2signer.signers.Blake2SerializerSigner): a signer class that handles data serialization, compression and encoding along with salted signing and salted timestamped signing. Its public methods are `dumps`, `loads`, `dumps_parts` and `loads_parts`, and `dump` and `load` for files.
* [**Blake2Signer**](signers.md#blake2signer.signers.Blake2Signer): a signer class that signs plain `bytes` or `str` data. Its public methods are `sign`, `unsign`, `sign_parts` and `unsign_parts`.
* [**Blake2TimestampSigner**](signers.md#blake2signer.signers.Blake2TimestampSigner): a signer class that timestamp signs plain `bytes` or `str` data. Its public methods are `sign`, `unsign`, `sign_parts` and `unsign_parts`.

**You should generally go for [Blake2SerializerSigner](signers.md#blake2signer.signers.Blake2SerializerSigner)**, given that it's the most versatile of the three, unless you need to deal with plain bytes or strings.

!!! tip
    [Serializing with JSON has a cost](performance.md#choosing-the-right-signer), even for small payloads (at least twice as much time as not serializing); so think about what you need to sign to pick the right signer. Also, note that [you can change the serializer](examples.md#using-a-custom-serializer) for better performance.

### Parameters

All [signers](signers.md) share the following instantiation parameters:

* `secret`: Secret value, which will be derived using BLAKE to produce the signing key. The minimum secret size is enforced to 16 bytes and there is no maximum. From v2.3.0, it can be a sequence of secrets instead of a single one, to support secret rotation, considering them ordered from oldest to newest, so that signatures are made with the newest secret but verifications are done using all of them.
* `personalisation`: Personalisation string (which will be derived using BLAKE) to force the hash function to produce different digests for the same input (no size limit).
* `digest_size`: Size of output signature (digest) in bytes (from v2.0.0 it defaults to 16, which is the minimum size allowed).
* `hasher`: Hash function to use, `blake2b` (default), `blake2s`, or from v2.2.0, `blake3`; the first one is optimized for 64b platforms; the second, for 8-32b platforms (read more about them in their [official site](https://blake2.net/)) and the third, for any platform (read more in the [official site](https://github.com/BLAKE3-team/BLAKE3-specs)).
* `deterministic`: (New in v1.2.0) Define if signatures are deterministic or non-deterministic (default). Non-deterministic sigs are preferred, and achieved through the use of a random salt (it can't be changed or set). For deterministic ones, no salt is used: this means that the result is idempotent, so for the same payload, the same sig is obtained (the advantage is that the sig is shorter, and producing it is faster).
* `separator`: (New in v2.0.0) Character to separate the signature, the timestamp and the payload. It must not belong to the encoder alphabet and be ASCII (defaults to `.`).
* `encoder`: (New in v2.0.0) Encoder class to use (defaults to a Base64 URL safe encoder). Note that `Blake2Signer` and `Blake2TimestampSigner` only encodes the signature, whereas `Blake2SerializerSigner` encodes everything.

Additionally, [*Blake2SerializerSigner*](signers.md#blake2signer.signers.Blake2SerializerSigner) supports the following:

* `max_age`: Use a timestamp signer instead of a regular one to ensure that the signature is not older than this time in seconds.
* `serializer`: Serializer class to use (defaults to a JSON serializer).
* `compressor`: Compressor class to use (defaults to a Zlib compressor).
* `compression_flag`: (New in v2.0.0) Character to mark the payload as compressed. It must not belong to the encoder alphabet and be ASCII (defaults to `.`).
* `compression_ratio`: (New in v2.0.0) The desired minimal compression ratio, between 0 and below 100 (defaults to 5). It is used to calculate when to consider a payload sufficiently compressed to detect detrimental compression. By default, if compression achieves less than 5% of size reduction, it is considered detrimental.

## About salt and personalisation

On all signers, a secure pseudorandom salt of the maximum allowed size for the hasher is generated for each signature internally and can't be manually set (salted signatures help to prevent breakage of a low-entropy key), meaning that every produced signature is non-deterministic, so even if the payload doesn't change, each signature will be different and unique. This, however, has a [performance cost](performance.md#randomness-is-expensive): non-deterministic signatures are a bit more expensive than deterministic ones.

??? example "Checking non-deterministic signatures"
    === "Source"

        ```python
        """Checking non-deterministic signatures."""

        from blake2signer import Blake2Signer 

        secret = b'one key to rule them all!'
        data = b'samwise the brave' 

        signer = Blake2Signer(secret) 

        signed1 = signer.sign(data)
        print('Signed 1:', signed1) 

        signed2 = signer.sign(data)
        print('Signed 2:', signed2) 

        # Signatures are different because they're non-deterministic: they contain
        # a salt
        print('Are signatures different?', signed1 != signed2)  # True
        ```

    === "Output"

        ```
        Signed 1: b'-QWpoUsxfjaYZ9ZdtClUNebzWKljrcUCQQnf5Q.samwise the brave'
        Signed 2: b'sYH3NoSGUyL0RVnxpq6y2eD42pdrnQrFRbHYhg.samwise the brave'
        Are signatures different? True
        ```

From v1.2.0, it is possible to generate deterministic signatures (meaning, without salt) using the `deterministic` option when instantiating any signer. For [`Blake2SerializerSigner`](signers.md#blake2signer.signers.Blake2SerializerSigner) this assumes that the serializer and compressor are always deterministic: if that is not true, then the signature won't be deterministic (encoders always are, and provided serializers and compressors are too), which isn't a problem on itself but just to clarify that the parameter doesn't do any magic.

Other packages usually refer to salt as something to mix with the secret to prevent signer misuse, but here we have the `personalisation` parameter for that.

!!! tip
    It is always a good idea to set the `personalisation` parameter. This helps to defeat the abuse of using a signed stream for different signers that share the same key by changing the digest computation result (read more about it in the [hashlib docs](https://docs.python.org/3/library/hashlib.html#personalization)). For example if you use a signer for cookies set something like `b'cookies-signer'` or if you use it for some user-related data signing it could be `b'user data signer'`, or when used for signing a special value it could be `b'the-special-value-signer`, etc.

It is important to note that the `personalisation` value doesn't need to be secret, nor a setting, nor random. It's perfectly fine to just be hardcoded in the class instantiation or similar, and different from any other personalisation value used (unique across all signers used).

??? example "Personalisation"
    ```python
    """Sample personalisation values."""

    from blake2signer import Blake2Signer, Blake2TimestampSigner

    secret = b'secret' * 3

    csrf_signer = Blake2Signer(secret, personalisation=b'signer for the form CSRF')
    cookies_signer = Blake2TimestampSigner(
        secret,
        personalisation=b'timed_signer_for_cookies',
    )

    ...
    ```

### Mixing signers

You can't mix and match signers, and that's on purpose: internally, to protect signed data to be mishandled, the `personalisation` parameter is populated with the signer characteristics such as its encoder, its class, its serializer, and compressor if any, etc - additionally to the given value -. This prevents a malicious user to use certain signed data to unsign it with a different signer.

However, you shouldn't solely rely on this characteristic: always set a proper `personalisation` value for the signer, even if it is the only signer in your application. See [examples](examples.md#using-personalisation) to know more.

??? example "Mixing signers example 1"
    === "Source"

        ```python
        """Mixing signers example 1."""

        from blake2signer import Blake2Signer
        from blake2signer.encoders import HexEncoder
        from secrets import token_hex 

        secret = b'it is OK to use the same secret for all signers' 

        s = Blake2Signer(secret, encoder=HexEncoder)
        signed = s.sign(token_hex(8))
        print('Signed:', signed) 

        s = Blake2Signer(secret)  # Use default base64 encoder
        s.unsign(signed)  # InvalidSignatureError: signature is not valid
        ```

    === "Output"

        ```
        Signed: b'41A815EB18C4EEE5086A7ABE247C4A59EFE4226A00FF0E29.471990bd764ee8de'
        Traceback (most recent call last):
          File "<stdin>", line 1, in <module>
          File ".../blake2signer/blake2signer/signers.py", line 135, in unsign
            return self._unsign(self._decompose(self._force_bytes(signed_data)))
          File ".../blake2signer/blake2signer/bases.py", line 480, in _unsign
            raise InvalidSignatureError('signature is not valid')
        blake2signer.errors.InvalidSignatureError: signature is not valid
        ```

??? example "Mixing signers example 2"
    === "Source"

        ```python
        """Mixing signers example 2."""

        from blake2signer import Blake2SerializerSigner
        from blake2signer import Blake2Signer
        from blake2signer import Blake2TimestampSigner
        from blake2signer import errors 

        secret = 'el problema es estructural'
        data = 'facundo castro presente' 

        t_signer = Blake2TimestampSigner(secret)
        s_signer = Blake2SerializerSigner(secret)
        signer = Blake2Signer(secret) 

        try:
            t_signer.unsign(s_signer.dumps(data), max_age=5.5)
        except errors.InvalidSignatureError as exc:
            print('Error:', repr(exc))  # InvalidSignatureError('signature is not valid') 

        try:
            signer.unsign(t_signer.sign(data))
        except errors.InvalidSignatureError as exc:
            print('Error:', repr(exc))  # InvalidSignatureError('signature is not valid') 

        try:
            s_signer.loads(signer.sign(data))
        except errors.InvalidSignatureError as exc:
            print('Error:', repr(exc))  # InvalidSignatureError('signature is not valid') 

        # Any and all combinations will produce an `InvalidSignatureError`...
        ```

    === "Output"

        ```
        Error: InvalidSignatureError('signature is not valid')
        Error: InvalidSignatureError('signature is not valid')
        Error: InvalidSignatureError('signature is not valid')
        ```

!!! note
    You could find your way to trick one class into accepting data generated by the other, but you really shouldn't! (the [tests](https://gitlab.com/hackancuba/blake2signer/-/tree/main/blake2signer/tests) may show you how if you are interested).

## About the secret

It is of the utmost importance that the secret value not only remains secret but also to be a cryptographically secure pseudorandom value. It can be arbitrarily long given that it is internally derived, along with the _personalisation_ value, to produce the signing key.

!!! success "Recommended way to generate a secret"
    From v3.1.0, you can generate a secret using the function `blake2signer.utils.generate_secret`. See [generating a secret](#generating-a-secret).

Usually the secret will be obtained from your app's settings or similar, which in turn will get it from the environment or some keyring or secret storage. Whichever the case, ensure that it has at least 256 bits of pseudorandom data, and **not** some manually splashed letters!.

!!! tip
    You can, and probably should, share the same secret with all the signers in use, there's no need to use a different one for each. Make sure to [set `personalisation` accordingly](#about-salt-and-personalisation), as this removes the complexity of having to maintain several different secrets.

### Generating a secret

You can generate the secret value in any of the following ways:

**Recommended**:

* `python3 -c 'from blake2signer.utils import generate_secret; print(generate_secret(), end="")'`

??? example "Generating and using a secret"
    === "Source"

        ```python
        """Generating a secret."""

        from blake2signer.utils import generate_secret


        secret = generate_secret()
        with open('.env', 'wt') as env_file:
            env_file.write(f'SECRET="{generate_secret()}"')

        print('Secret saved in .env file:', secret)
        ```

        ```python
        """Using a secret from env."""

        import os

        from blake2signer import Blake2Signer


        def read_secret() -> str:
            """Toy example of reading a secret from env vars or a file."""
            secret = os.getenv('SECRET')
            if secret:
                return secret

            # Normally, the env var is loaded into the application environment, so this file
            # is supposed to be interpreted by a shell. In this toy example, we read from
            # the file and parse it, which is not recommended to do in a production system
            # like this.
            with open('.env') as env_file:
                for line in env_file:
                    if line.startswith('SECRET='):
                        secret = line.strip().removeprefix('SECRET="').removesuffix('"')
                        if secret:
                            return secret

                        break

            raise RuntimeError('Secret value could not be found')

        secret = read_secret()
        data = b"YMMV"

        signer = Blake2Signer(secret)

        print(
            'Does signing and unsigning works?',
            data == signer.unsign(signer.sign(data)),  # True
        )
        ```

    === "Output"

        ```
        Secret saved in .env file: 2iLJRCcUEQMukjghDCU5BTjnUZg4JmsmV759TswSPDDwQU6uHgkt1p9vnanpzSMuPdJKC3GU39kjBMsEk1XyexSQ
        ```

        ```
        Does signing and unsigning works? True
        ```

Base64 encoded:

* `python3 -c 'import secrets; print(secrets.token_urlsafe(64), end="")'`
* `dd if=/dev/urandom iflag=fullblock bs=64 count=1 status=none | base64 -w0 | tr '/+' '_-' | tr -d '='`
* `openssl rand -base64 64 | tr '/+' '_-' | tr -d '\n='`

Hex encoded:

* `python3 -c 'import secrets; print(secrets.token_hex(64), end="")'`
* `od -vN 64 -An -tx1 /dev/urandom | tr -d '[:space:]'`
* `xxd -l 64 -p /dev/urandom | tr -d '\n'`
* `hexdump -vn 64 -e ' /1 "%02x"' /dev/urandom`
* `openssl rand -hex 64 | tr -d '\n'`

The encoding doesn't matter, the secret value is used as-is, and derived to obtain the key.

### Secret rotation

!!! info "New in v2.3.0"
    The `secret` parameter can be bytes, strings or any sequence of them (list, tuple, etc.).

From v2.3.0, `secret` can also be a sequence of secrets instead of a single one to support _secret rotation_, considering them ordered from oldest to newest, so that signatures are made with the newest secret but verifications are done using all of them.  Every secret must comply with the restrictions enforced as a single secret does.

An external system can maintain the list of secrets, periodically removing old ones. This provides additional protection against secret leakage or potential bruteforce, and is always a recommended practice. This system is out of the scope for this project, but the mechanism is fully supported.

When a new secret is added to the list, all new signatures will be done with it, whereas signature verifications will consider every possible secret from the list. After a certain amount of time, the system can assume that every active user has received a new signature, thus being able to remove an old secret from the list without disturbing users nor interfering with other parts of the system.

Do note that this has a certain performance impact if many secrets are in said list, and a verification process is presented with a very old secret (say, the oldest one): the signer will go secret by secret, from newest to oldest, to verify this signature thus costing as much as making N signatures, where N is the number of secrets.

You should consider this situation to define the number of times you rotate the secret, and how long should they last. In example, rotating the secret daily and maintaining a monthly list can have a deep negative performance impact; rotating weekly or monthly and keeping four or less would not have a very noticeable impact, and the security benefits of this practice would prevail over the potential performance issue.

!!! tip
    The secret rotation mechanism is compatible with [ItsDangerous](https://itsdangerous.palletsprojects.com/en/2.0.x/concepts/#key-rotation)' one.

### Changing the secret size limit

The secret value is enforced to be of a minimum length of 16 bytes, but this can be changed: either to a bigger or lower value. A longer secret is always a good idea, and there is no limit for this given that [its value is derived](details.md#about-the-secret) to produce the hashing key.  
To change the limit, set the class attribute [`MIN_SECRET_SIZE`](bases.md#blake2signer.bases.Base.MIN_SECRET_SIZE) to the desired value in bytes.

!!! danger
    Reducing the secret size lower than 8 bytes (128 bits) poses an increasing security risk.

!!! info "This can be done in every signer"

??? example "Changing the secret size limit"
    === "Source"

        ```python
        """Changing the secret size limit."""

        from blake2signer import Blake2Signer
        from blake2signer import errors

        secret = b'Han shot first'
        data = b"didn't he?"

        try:
            signer = Blake2Signer(secret)
        except errors.InvalidOptionError as exc:
            print('Error:', repr(exc))  # secret should be longer than 16 bytes

        Blake2Signer.MIN_SECRET_SIZE = 8  # Size in bytes
        signer = Blake2Signer(secret)

        print(
            'Does signing and unsigning works w/ short secrets?',
            data == signer.unsign(signer.sign(data)),  # True
        )
        ```

    === "Output"

        ```
        Error: InvalidOptionError('the 1st secret should be longer than 16 bytes')
        Does signing and unsigning works w/ short secrets? True
        ```

!!! warning
    All instances of the signer are affected by the class attribute change.

## Encoders, Serializers, and Compressors

Signers support changing the encoder class (from v2.0.0) and [*Blake2SerializerSigner*](signers.md#blake2signer.signers.Blake2SerializerSigner) also support changing the serializer and compressor. This package provides several encoders, serializers and compressors in their respective submodules:

* Encoders
    * Base64 URL safe encoder: uses only lowercase and uppercase English alphabet letters, numbers, underscore (`_`) and hyphen (`-`).
    * Base32 encoder: uses only uppercase English alphabet letters, and the numbers 2 to 7.
    * Hex/Base16 encoder: uses only numbers, and the uppercase English alphabet letters from A to F.
    * Base58 encoder: (from v3.1.0) uses only numbers from 1 to 9, and the uppercase and lowercase English alphabet letters, except for `I`, `O` and `l` to improve human readability and reduce transcription errors.
* Serializers
    * JSON serializer: serializes most Python basic types into a string in [JSON](https://www.json.org/json-en.html).
    * Null serializer: doesn't serialize, but otherwise converts given input to `bytes`.
* Compressors
    * Zlib compressor: compresses using [ZLib](https://zlib.net/).
    * Gzip compressor: compresses using [GZip](https://www.gzip.org/).

!!! tip "New in v0.4.0"
    You can create a custom encoder simply inheriting from [`EncoderInterface`](interfaces.md#blake2signer.interfaces.EncoderInterface), a custom compressor inheriting from [`CompressorInterface`](interfaces.md#blake2signer.interfaces.CompressorInterface) and a custom serializer inheriting from [`SerializerInterface`](interfaces.md#blake2signer.interfaces.SerializerInterface), and you don't need to handle or worry about exceptions: those are caught by the caller class.

!!! info "New in v2.0.0"
    All interfaces live in the [`interfaces`](interfaces.md) submodule.

Check examples on how to use existing [encoders](examples.md#changing-the-encoder), [compressors](examples.md#changing-the-compressor) and [serializers](examples.md#changing-the-serializer), or how to create a [custom serializer](examples.md#using-a-custom-serializer), [encoder](examples.md#using-a-custom-encoder) or [compressor](examples.md#using-a-custom-compressor) or even a [custom serializer signer class](examples.md#creating-a-custom-serializersigner-class).

### Compression level

[*Blake2SerializerSigner*](signers.md#blake2signer.signers.Blake2SerializerSigner) can optionally [compress data](examples.md#compressing-data) after serializing it to make the resulting signature shorter. From v2.1.0, the default compression level depends on the compressor and is no longer hardcoded to 6. For example, Zlib defaults to 6 but Gzip, to 9.

No matter which compressor is used, it will always be a value between 1 and 9, where 1 is the fastest and least compressed and 9 the slowest and most compressed. Should a compressor in particular use a different scale, then a conversion is internally done, so the end user doesn't have to deal with those details, and the interface remains homogeneous.

A high compression level usually implies a big hit to performance, taking more CPU time and/or memory to compress and decompress, but achieving smaller outputs. So if you have a particular constraint, then you can set the level according to your constraint and test to see if the result is as expected.

!!! note "No worries"
    Usually, there's no need to set the compression level to a particular value, and therefore there's no need to worry about it, and it can be left by default. However, if you need to, you can.

## Exceptions

In this package, every exception is subclassed from [`SignerError`](errors.md#blake2signer.errors.SignerError) (except for a [`RuntimeError` that will happen in ~2106-02-07](https://gitlab.com/hackancuba/blake2signer/-/blob/fcc2588939895c428d7b3420fbddaab62d864b88/blake2signer/bases.py#L462-465), if this library is unmaintained by then). You can read more about [errors and exceptions](errors.md) in its page.

There is one particular exception that is different from the rest: [`ExpiredSignatureError`](errors.md#blake2signer.errors.ExpiredSignatureError). This exception, raised when a signature has expired, but is valid, can hold the timestamp indicating when the signature was done, as an aware datetime object in UTC (from v2.0.0), and the _valid_ unsigned data payload (from v2.5.0).  Since the signature is valid and correct, it is OK to access its unsigned data value. Just be aware that its time-to-live has expired, according to your own settings.

It is important to note that if said exception is raised by a serializer signer, then the data contained in it is not the original unsigned data but a serialized/compressed/encoded one. Therefore, in such cases, one must use the method [`data_from_exc`](signers.md#blake2signer.signers.Blake2SerializerSigner.data_from_exc).

??? example "Reading data from an ExpiredSignatureError exception"
    === "Source"

        ```python
        """Reading data from an ExpiredSignatureError exception."""
        from time import sleep

        from blake2signer import Blake2SerializerSigner, errors


        data = {'some': 'data'}
        secret = 'just some very secret secret'

        signer = Blake2SerializerSigner(secret, max_age=3)
        signed = signer.dumps(data)

        sleep(3)

        try:
            signer.loads(signed)
        except errors.ExpiredSignatureError as exc:
            print('Error:', repr(exc))
            # The signature expired, but it is a good sig, so data is safe
            print(
                'Serialized/compressed/encoded data in exc:',
                exc.data,  # It's a bytes value that is serialized/compressed/encoded
            )
            unsigned = signer.data_from_exc(exc)
            print('Data from exc:', unsigned)  # Now we have the original data
            print('Does it match original data?', data == unsigned)  # True
        ```

    === "Output"

        ```
        Error: ExpiredSignatureError(signature has expired, age 3.036761522293091 > 3.0 seconds)
        Serialized/compressed/encoded data in exc: b'eyJzb21lIjoiZGF0YSJ9'
        Data from exc: {'some': 'data'}
        Does it match original data? True
        ```

This can be used to act upon such an event, like informing something to a user. Again, do note that the signature is expired!.

Check the [limiting signature lifetime](examples.md#limiting-signature-lifetime) and [the ExpiredSignatureError exception](examples.md#the-expired-signature-exception) examples.
