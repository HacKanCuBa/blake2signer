# Upgrade guide

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
