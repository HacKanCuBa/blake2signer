# Upgrade guide

## To v2.5

!!! success "Old signatures will work"
    Data signed with previous versions (>=2.0, <=2.4) will still be valid.

Now the [`ExpiredSignatureError` exception](errors.md#blake2signer.errors.ExpiredSignatureError) contains valid unsigned data, which can be safely used. Check out [the example](examples.md#the-expired-signature-exception) to know more.

## To v2.4

!!! success "Old signatures will work"
    Data signed with previous versions (>=2.0, <=2.4) will still be valid.

Both the public and private API of Blake2TimestampSigner for `unsign` and `unsign_parts` now accepts `max_age=None` to omit checking the signature timestamp (but note that there is no default! it has to be explicit). This happens after checking the signature, which must be valid.

Checkout the [examples](examples.md#choosing-when-to-check-the-timestamp).

## To v2.3

!!! success "Old signatures will work"
    Data signed with previous versions (>=2.0, <=2.3) will still be valid.

For the public API, the constructor for signers now accept as the _secret_, besides string or bytes, a sequence of string or bytes, to allow for [secret rotation](examples.md#rotating-the-secret). This means you don't have to change anything unless you want to start using said feature.

Regarding the private API, a few internal methods were modified to work with this sequence of secrets. Check out the corresponding commit:

* [`5a0b22d5`](https://gitlab.com/hackancuba/blake2signer/-/commit/5a0b22d5949ffed4010cfb9d1b75d1660d682269) - ✨ Support secret rotation

## To v2.2

!!! success "Old signatures will work"
    Data signed with previous versions (>=2.0, <=2.2) will still be valid.

No public API was changed, so there's no change for you except that you can now choose to use `blake3`.

Regarding the private API, several internal methods of the signers changed, and many were transferred to the `BLAKEHasher` class, and subclasses. Check out the corresponding commit and [docs](hashers.md):

* [`abd17905`](https://gitlab.com/hackancuba/blake2signer/-/commit/abd17905cf571b25aa001329a0c815338161c947) - ✨ Add support for BLAKE3

## To v2.1

!!! success "Old signatures will work"
    Data signed with previous versions (>=2.0, <=2.1) will still be valid.

The default compression level was hardcoded to 6 no matter which compressor was being used. This has changed so that the corresponding default compression level for the compressor is used.

If you were using the Zlib compressor (default), then there's no change for you. However, if you were using the Gzip compressor, the default level will now be 9 instead of 6. To continue using 6 as compression level, change the line calling the corresponding method (dump, dumps or dumps_parts) and use the parameter `compression_level=6`:

```python
from blake2signer import Blake2SerializerSigner


secret = b'secure-secret-that-nobody-knows!'
data = {'user_id': 1, 'is_admin': True, 'username': 'hackan'}

signer = Blake2SerializerSigner(
    secret,
    personalisation=b'some-signer',
)
# ...
signed = signer.dumps(data, compression_level=6)  # Add the compression_level parameter
```

See the [examples](examples.md#compressing-data) for more information.

Moreover, if you have created a custom compressor, then you need to add the `default_compression_level` property:

```python
from blake2signer.interfaces import CompressorInterface


class MyCompressor(CompressorInterface):
    """My compressor."""

    @property
    def default_compression_level(self) -> int:
        """Get the default compression level."""
        return 8

    ...
```

See the [examples](examples.md#using-a-custom-compressor) for more information.

## To v2

Generally speaking, *v2 broke the public API a bit*, so most projects using v1 *could probably* work as-is with v2. However, the private API changed **a lot**.

!!! abstract "Old signatures will fail"
    Data signed with previous versions fails with `InvalidSignatureError`.

### Public API changes

* `Blake2Signer|Blake2TimestampSigner|Blake2SerializerSigner.SEPARATOR` class attribute is replaced by the `separator` instance attribute and is now checked to be ASCII only and not belong to the encoder alphabet.
* `Blake2SerializerSigner.COMPRESSION_FLAG` class attribute is replaced by the `compression_flag` instance attribute and is now checked to be ASCII only.
* `Blake2SerializerSigner.COMPRESSION_RATIO` class attribute is replaced by the `compression_ratio` instance attribute and is now checked to be ASCII only.
* The default digest size for all signers is set to 16 bytes. Previously, `Blake2Signer` and `Blake2TimestampSigner` defaulted to the maximum allowed size for the hasher.
* The compression parameter used in `Blake2SerializerSigner` named `use_compression` is renamed to `compress`.

### Private API changes

The private API changed **a lot**, so if you were using some private methods please review them for changes! Unfortunately [I can't list them all here](https://gitlab.com/hackancuba/blake2signer/-/commits/2.0.0) but mainly check these commits:

* [`c6acaa0a`](https://gitlab.com/hackancuba/blake2signer/-/commit/c6acaa0a8f0d2c7d45145df09a3b8dbd4c8f9948) - 🏗 Split classes into own modules by type
* [`0b1d0a6c`](https://gitlab.com/hackancuba/blake2signer/-/commit/0b1d0a6ccb8a7107c40f3d967c03f411ebc3f377) - ✨ Allow changing encoder in every signer
* [`c9bcd173`](https://gitlab.com/hackancuba/blake2signer/-/commit/c9bcd1733643a6320a1ff579a69be92af6dda713) - ✨ Make separator an instance attribute
* [`675389de`](https://gitlab.com/hackancuba/blake2signer/-/commit/675389dedaf4aff22e0ae061069018dae596dc0f) - ✨ Make comp flag and ratio an instance attribute
* [`8618e663`](https://gitlab.com/hackancuba/blake2signer/-/commit/8618e663c7b8d4f957d15439776347cc8e048e17) - ♻ Refactor serializer signer base methods
* [`40ccbd40`](https://gitlab.com/hackancuba/blake2signer/-/commit/40ccbd40c2a3125daee6c4012c4681460aeb6e3a) - ✨ Add new methods to get data and sig separately
* [`b2d69910`](https://gitlab.com/hackancuba/blake2signer/-/commit/b2d699101cc9a97c8f0f1632eebdc2ec74646053) - ♻ Rename `use_compression` to `compress`
