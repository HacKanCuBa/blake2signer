# Details

Some details and general information about the signers in this lib.

## Signers

This module provides three signer classes:

* **Blake2SerializerSigner**: a signer class that handles data serialization, compression and encoding along with salted signing and salted timestamped signing. Its public methods are `dumps`, `loads`, `dumps_parts` and `loads_parts`, and `dump` and `load` for files.
* **Blake2Signer**: a signer class that simply salts, signs and verifies signed data as bytes or string. Its public methods are `sign`, `unsign`, `sign_parts` and `unsign_parts`.
* **Blake2TimestampSigner**: a signer class that simply salts, signs and verifies signed timestamped data as bytes or string. Its public methods are `sign`, `unsign`, `sign_parts` and `unsign_parts`.

**You should generally go for Blake2SerializerSigner**, given that it's the most versatile of the three, unless you need to deal with plain bytes or string.

!!! tip
    [Serializing with JSON has a cost](performance.md#choosing-the-right-signer), even for small payloads (at least twice as much time as not serializing); so think about what you need to sign to pick the right signer. Also, note that [you can change the serializer](examples.md#using-a-custom-serializer) for better performance.

### Parameters

All [signers](signers.md) share the following instantiation parameters:

* `secret`: Secret value (which will be derived using BLAKE2) to produce the signing key (the minimum size required is 16 bytes, no size limit).
* `personalisation`: Personalisation string (which will be derived using BLAKE2) to force the hash function to produce different digests for the same input (no size limit).
* `digest_size`: Size of output signature (digest) in bytes (since v2.0.0 it defaults to 16, which is the minimum size allowed).
* `hasher`: Hash function to use, either `blake2b` (default) or `blake2s`; the first one is optimized for 64b platforms, and the second, for 8-32b platforms (read more about them in their [official site](https://blake2.net/)).
* `deterministic`: (New in v1.2.0) Define if signatures are deterministic or non-deterministic (default). Non-deterministic sigs are preferred, and achieved through the use of a random salt (it can't be changed or set). For deterministic sigs, no salt is used: this means that for the same payload, the same sig is obtained (the advantage is that the sig is shorter).
* `separator`: (New in v2.0.0) Character to separate the signature, the timestamp and the payload. It must not belong to the encoder alphabet and be ASCII (defaults to `.`).
* `encoder`: (New in v2.0.0) Encoder class to use (defaults to a Base64 URL safe encoder). Note that `Blake2Signer` and `Blake2TimestampSigner` only encodes the signature, whereas `Blake2SerializerSigner` encodes everything.

Additionally, *Blake2SerializerSigner* supports the following:

* `max_age`: Use a timestamp signer instead of a regular one to ensure that the signature is not older than this time in seconds.
* `serializer`: Serializer class to use (defaults to a JSON serializer).
* `compressor`: Compressor class to use (defaults to a Zlib compressor).
* `compression_flag`: (New in v2.0.0) Character to mark the payload as compressed. It must not belong to the encoder alphabet and be ASCII (defaults to `.`).
* `compression_ratio`: (New in v2.0.0) Desired minimal compression ratio, between 0 and below 100 (defaults to 5). It is used to calculate when to consider a payload sufficiently compressed to detect detrimental compression. By default, if compression achieves less than 5% of size reduction, it is considered detrimental.

## About salt and personalisation

On all signers a secure pseudorandom salt of the maximum allowed size for the hasher is generated for each signature internally and can't be manually set (salted signatures helps to prevent breakage of a low-entropy key), meaning that every produced signature is non-deterministic so even if the payload doesn't change each signature will be different and unique.

??? example "Checking non-deterministic signatures"
    ```python
    """Checking non-deterministic signatures."""

    from blake2signer import Blake2Signer

    secret = b'one key to rule them all!'
    data = b'samwise the brave'

    signer = Blake2Signer(secret)

    signed1 = signer.sign(data)
    print(signed1)

    signed2 = signer.sign(data)
    print(signed2)

    # Signatures are different because they're non-deterministic: they contain
    # a salt
    print(signed1 != signed2)  # True
    ```

Since v1.2.0, it is possible to generate deterministic signatures (meaning, without salt) using the `deterministic` option when instantiating any signer. For `Blake2SerializerSigner` this assumes that the serializer and compressor are always deterministic: if that is not true, then the signature won't be deterministic (encoders always are, and provided serializers and compressors are too), which isn't a problem on itself but just to clarify that the parameter doesn't do any magic.

Other packages usually refer to salt as something to mix with the secret to prevent signer misuse, but here we have the `personalisation` parameter for that.

!!! tip
    It is always a good idea to set the `personalisation` parameter. This helps to defeat the abuse of using a signed stream for different signers that share the same key by changing the digest computation result (read more about it in the [hashlib docs](https://docs.python.org/3/library/hashlib.html#personalization)). For example if you use a signer for cookies set something like `b'cookies-signer'` or if you use it for some user-related data signing it could be `b'user data signer'`, or when used for signing a special value it could be `b'the-special-value-signer`, etc.

### Mixing signers

You can't mix and match signers, and that's on purpose: internally, to protect signed data to be mishandled, the `personalisation` parameter is populated with the signer characteristics such as its encoder, its class, its serializer and compressor if any, etc - additionally to the given value -. This prevents a malicious user to use certain signed data to unsign it with a different signer.

However, you shouldn't solely rely on this characteristic: always set a proper `personalisation` value for the signer, even if it is the only signer in your application. See [examples](examples.md#using-personalisation) to know more.

??? example "Mixing signers example 1"
    ```python
    """Mixing signers example 1."""

    from blake2signer import Blake2Signer
    from blake2signer.encoders import HexEncoder
    from secrets import token_hex

    secret = b'it is OK to use the same secret for all signers'

    s = Blake2Signer(secret, encoder=HexEncoder)
    signed = s.sign(token_hex(8))
    print(signed)

    s = Blake2Signer(secret)  # Use default base64 encoder
    s.unsign(signed)  # InvalidSignatureError: signature is not valid
    ```

??? example "Mixing signers example 2"
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
        print(repr(exc))  # InvalidSignatureError('signature is not valid')

    try:
        signer.unsign(t_signer.sign(data))
    except errors.InvalidSignatureError as exc:
        print(repr(exc))  # InvalidSignatureError('signature is not valid')

    try:
        s_signer.loads(signer.sign(data))
    except errors.InvalidSignatureError as exc:
        print(repr(exc))  # InvalidSignatureError('signature is not valid')

    # Any and all combinations will produce an `InvalidSignatureError`...
    ```

!!! note
    You could find your way to trick one class into accepting data generated by the other, but you really shouldn't! (the [tests](https://gitlab.com/hackancuba/blake2signer/-/tree/main/blake2signer/tests) may show you how if you are interested).

## About the secret

It is of utmost importance that the secret value not only remains secret but also to be a cryptographically secure pseudorandom value. It can be arbitrarily long given that it is internally derived, along with the personalisation value, to produce the signing key.

Usually the secret will be obtained from your app's settings or similar, which in turn will get it from the environment or some keyring or secret storage. Whichever the case, ensure that it has at least 256 bits of pseudorandom data, and **not** some manually splashed letters!.

!!! tip
    You can share the same secret with all the signers in use, there's no need to use a different secret for each. Just make sure to [set `personalisation` accordingly](#about-salt-and-personalisation).

You can generate the secret value in any of the following ways:

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

### Changing the secret size limit

The secret value is enforced to be of a minimum length of 16 bytes, but this can be changed: either to a bigger or lower value. A longer secret is always a good idea, and there is no limit for this given that [its value is derived](details.md#about-the-secret) to produce the hashing key.  
To change the limit, set the class attribute `MIN_SECRET_SIZE` to the desired value in bytes.

!!! danger
    Reducing the secret size lower than 8 bytes (128 bits) poses an increasing security risk.

!!! info "This can be done in every signer"

??? example "Changing the secret size limit"
    ```python
    """Changing the secret size limit."""

    from blake2signer import Blake2Signer
    from blake2signer import errors

    secret = b'Han shot first'
    data = b"didn't he?"

    try:
        signer = Blake2Signer(secret)
    except errors.InvalidOptionError as exc:
        print(exc)  # secret should be longer than 16 bytes
        Blake2Signer.MIN_SECRET_SIZE = 8  # Size in bytes
        signer = Blake2Signer(secret)

    print(data == signer.unsign(signer.sign(data)))  # True
    ```

!!! warning
    All instances of the signer are affected by the class attribute change.

## Encoders, Serializers and Compressors

Signers support changing the encoder class (since v2.0.0) and *Blake2SerializerSigner* also support changing the serializer and compressor. This package provides several encoders, serializers and compressors in their respective submodules:

* Encoders
    * Base64 URL safe encoder: uses only lowercase and uppercase English alphabet letters, numbers, underscore (`_`) and hyphen (`-`).
    * Base32 encoder: uses only uppercase English alphabet letters, and the numbers 2 to 7.
    * Hex/Base16 encoder: uses only numbers, and the uppercase English alphabet letters from A to F. 
* Serializers
    * JSON serializer: serializes most Python basic types into a string in [JSON](https://www.json.org/json-en.html).
    * Null serializer: doesn't serialize, but otherwise converts given input to bytes.
* Compressors
    * Zlib compressor: compresses using [ZLib](https://zlib.net/).
    * Gzip compressor: compresses using [GZip](https://www.gzip.org/).

!!! tip "New in v0.4.0"
    You can create a custom encoder simply inheriting from `EncoderInterface`, a custom compressor inheriting from `CompressorInterface` and a custom serializer inheriting from `SerializerInterface`, and you don't need to handle or worry about exceptions: those are caught by the caller class.

!!! info "New in v2.0.0"
    All interfaces live in the `interfaces` submodule.

Check examples on how to use existing [encoders](examples.md#changing-the-encoder), [compressors](examples.md#changing-the-compressor) and [serializers](examples.md#changing-the-serializer), or how to create a [custom serializer](examples.md#using-a-custom-serializer), [encoder](examples.md#using-a-custom-encoder) or [compressor](examples.md#using-a-custom-compressor) or even a [custom serializer signer class](examples.md#creating-a-custom-serializersigner-class).
