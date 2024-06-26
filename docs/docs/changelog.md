# Changelog

## 3.1.0 - 2024-04-22

**Added**

- Add Base58 encoder, and some example usages like creating signed API keys.
- Add utility function to generate a secure secret: `blake2signer.utils.generate_secret`.
- Add `create-archives` Invoke task, to aide on signing releases.

**Changed**

- Always mock current time on timestamp signers tests, which makes testing timestamp-related signers easier, and less error-prone.
- Fix Invoke tests task cancellation: prevent one test command failure to cancel the execution of the rest, thus still having a `report.xml` file generated, while exiting with the proper error code.
- Change the fuzz task to allow selecting a specific signer.
- Change fuzz CI job to fuzz all signers in parallel.

## 3.0.0 - 2024-01-25

**Added**

- Add new create signed tag Invoke task.

**Removed**

- Drop Python 3.7.

**Changed**

- Update dev dependencies.
- Improve Invoke tasks with type hints.
- Improve docs and docstrings grammar and wording.
- [Normalize file-related operations to use bytes](performance.md#the-same-goes-for-files), so we can default to open the file in binary mode for better performance.
- [`force_bytes`](utils.md#blake2signer.utils.force_bytes) and [`force_string`](utils.md#blake2signer.utils.force_string) utility functions now only accept either `bytes` or `str`, and raises `TypeError` otherwise. However, signers usages are not affected by this.
- Upgrade docs Python version to 3.10.

**Fixed**

- Fix tests that were failing in PyPy due to `time` not being patched.

## 2.5.3 - 2023-12-21

*Note: This is the last version supporting Python 3.7!*

**Changed**

- Update dev, and docs dependencies.
- Update test runner in the CI for Python 3.12, 3.13-pre and PyPy 3.10.
- Update new version release guide in docs to use minisign.
- Replace deprecated pkg_resources with importlib.
- Replace deprecated datetime.utcnow in Invoke tasks.
- Other minor linting changes due to linter updates.

## 2.5.2 - 2023-02-25

**Added**

- Add missing keywords in pyproject.toml.

**Removed**

- Remove invoke patch for Python 3.11+: it's been fixed now, so it's no longer needed.

**Changed**

- Improve some docs.
- Update dev, and docs dependencies.

**Fixed**

- Fix issue with mkdocstrings and blake3.

## 2.5.1 - 2022-12-04

**Added**

- Patch Invoke so it works under Python 3.11+.

**Changed**

- Improve the fuzzing script, add instructions on running it, and add it as a CI job for releases.
- Change the usage of `AnyStr` in signer's public methods with `Union[str, bytes]`, which is not the same, and they are not generally interchangeably like this, but for this particular usage Union makes more sense, and MyPy seems to agree with this.
- Several improvements in the CI: fixed coverage report, updated Python versions and Poetry, added fuzzing, etc.
- Update dev dependencies.

## 2.5.0 - 2022-07-02

**Added**

- Add valid unsigned data to the [`ExpiredSignatureError` exception](examples.md#the-expired-signature-exception): even if the signature is expired, its unsigned value is valid and safe, so now it can be used.
- Add new linters: pylint, and perflint.

**Changed**

- Move docs to its own environment, due to some incompatibility between dev dependencies. This results in better handling of docs dependencies, using Poetry.
- Several docs, and docstrings improvements.

**Security**

- Implement [minisign](https://jedisct1.github.io/minisign/) to sign all release packages, and tags (using [git-minisign](https://gitlab.com/hackancuba/git-minisign>)), instead of [PGP](https://gist.github.com/HacKanCuBa/afe0073fe35fddf01642220acd4cde17). Read more [in the docs](signatures.md).
- Run `safety` scanner over docs dependencies too.

## 2.4.0 - 2022-03-27

**Added**

- Add tests to ensure compatibility, or not, with previous versions.

**Changed**

- [Allow `max_age` to be None](examples.md#choosing-when-to-check-the-timestamp) for the [`Blake2TimestampSigner`](signers.md#blake2signer.signers.Blake2TimestampSigner): the timestamp is then not checked (but the signature is always checked).

## 2.3.0 - 2022-02-23

**Added**

- Add support for [signing secret rotation](examples.md#rotating-the-secret): now it supports receiving a sequence of secrets instead of a single one, considering them ordered from oldest to newest, so that signatures are made with the newest secret but verifications are done using all of them.
- Add dev tool `darglint` to help checking docstrings consistency with the code, and consequently improve docstrings adding missing parts.

## 2.2.0 - 2022-01-24

**Added**

- Add [support for BLAKE3](examples.md#using-blake3) through third-party package `blake3`, which are bindings to the homonym Rust package (ported by one of the algorithm's author).

**Changed**

- Several docs content improvements.
- Marginal performance improvement by changing frozen dataclasses for named tuples.

## 2.1.0 - 2021-12-28

**Changed**

- [Unhardcode default compression level](details.md#compression-level), which was hardcoded to 6. That value was set for Zlib and remained there since the old times. Make the default `None` so we can let the compressor set the right value.

## 2.0.0 - 2021-06-11

**Added**

- Allow [changing encoder in every signer](examples.md#changing-the-encoder): previously only Blake2SerializerSigner accepted encoders other than b64, yet not totally: the signature was always b64 URL safe encoded. This required a slight refactor splitting the signers' module into bases and signers.
- Add new base32 encoder.
- Add check to ensure that the separator does not belong to the encoder alphabet.
- Add new hex (base16) encoder.
- Add check to ensure that the separator and compressor flag are ASCII characters to prevent encoding errors when converting from bytes to string.
- Add new gzip compressor.
- Add new [null serializer](examples.md#using-the-nullserializer): a serializer that doesn't actually serialize. It can be useful when you need to manage bytes or strings, but you want to compress too, therefore being able to use the Blake2SerializerSigner for this.
- Add check to ensure that the separator and compressor flag are not empty.
- Add check to ensure that the encoder alphabet is ASCII and not empty.
- Add signature timestamp to [`ExpiredSignatureError`](errors.md#blake2signer.errors.ExpiredSignatureError) exception in new `timestamp` parameter as an aware datetime object.
- Add new [dump](signers.md#blake2signer.signers.Blake2SerializerSigner.dump)/[load](signers.md#blake2signer.signers.Blake2SerializerSigner.load) interface in [`Blake2SerializerSigner`](signers.md#blake2signer.signers.Blake2SerializerSigner) for file-like objects.
- Add argument to [`Blake2SerializerSigner.dumps()`](signers.md#blake2signer.signers.Blake2SerializerSigner.dumps) to pass keyword arguments to the serializer.
- Add documentation with mkdocs, and a nice title with logo (many thanks to Erus).
- Add new methods to obtain data and signature separately for all signers: [`sign_parts`](signers.md#blake2signer.signers.Blake2Signer.sign_parts)/[`unsign_parts`](signers.md#blake2signer.signers.Blake2Signer.unsign_parts), and [`dumps_parts`](signers.md#blake2signer.signers.Blake2SerializerSigner.dumps_parts)/[`loads_parts`](signers.md#blake2signer.signers.Blake2SerializerSigner.loads_parts).
- Create a security scanning job using [Trivy](https://aquasecurity.github.io/trivy/).
- Add a job to test support for [PyPy](https://www.pypy.org) 3.7.
- Add a job to test support for [Stackless Python](https://github.com/stackless-dev/stackless/wiki) 3.7.

**Changed**

- Split classes between [mixins](mixins.md) and [interfaces](interfaces.md); also [serializers](serializers.md), [compressors](compressors.md) and [encoders](encoders.md), which are implementations of [interfaces](interfaces.md). This smooths the way to have several implementors and to actually be able to change the entire encoding in the future (currently the signature is always b64 URL safe encoded even if the encoder is changed in Blake2SerializerSigner).
- Set default digest size for all signers to 16 bytes, so the output and functioning is more homogeneous.
- Make compression flag and ratio an instance attribute.
- Make separator an instance attribute.
- Change type annotations for secret, personalisation, separator and compression_flag to show support for bytes and string as it has always been supported.
- Improve [force_bytes](utils.md#blake2signer.utils.force_bytes) performance by not casting bytes to bytes, and change its signature to accept any.
- Rename `use_compression` to `compress` because it's shorter and easier to write, and more tab-autocompletion friendly.
- Recover cause in all exceptions for easier debugging. This was not done before on purpose to hide information in case a misconfiguration in the implementor application would expose said information to the public, but the benefits of having a cause traceback to the original exception are too many to not have it.
- Split tests by module or class to avoid having a giant single file with all the tests in it.
- Marginally improve performance, around ~4% less time, to sign and unsign by removing unneeded calls to `force_bytes` when encoding/decoding.

**Security**

- Prevent timestamped signatures "from the future" to pass as correct by checking the signature age to be bigger than 0.
- Create a fuzzing script using `pythonfuzz` to uncover unexpected bugs.
- Fix a potential vulnerability when the [`NullSerializer`](serializers.md#blake2signer.serializers.NullSerializer) was used, and the user could sign arbitrary data, then a malicious user could sign a zip bomb that when unsigned could cause at best a controlled [`DecompressionError`](errors.md#blake2signer.errors.DecompressionError) exception or at worst a DoS or other unknown result (depends heavily on the compressor used). This scenario is not default and probably very hard to achieve (it can't be produced with the [`JSONSerializer`](serializers.md#blake2signer.serializers.JSONSerializer) but it could perhaps be produced by some other custom serializer too), but nevertheless the possibility was there.

## 1.2.1 - 2021-05-10

**Added**

- Add jobs to publish python packages automatically.

**Fixed**

- Fix wrong exception being raised in [`Blake2TimestampSignerBase._decode_timestamp()`](bases.md#blake2signer.bases.Blake2TimestampSignerBase._decode_timestamp).

## 1.2.0 - 2021-04-24

**Added**

- Add setting to allow [deterministic signatures](examples.md#generating-deterministic-signatures), but keep default of non-deterministic ones.

## 1.1.0 - 2021-04-15

**Added**

- Add new `force_compression` parameter in [`Blake2SerializerSigner.dumps()`](signers.md#blake2signer.signers.Blake2SerializerSigner.dumps) to expose existing capability to [force data compression](examples.md#compressing-data).

**Changed**

- Change execution order of steps to publish a package in [Contrib](contrib.md), to allow room for fixes after publishing to testpypi.
- Reworded and fixed some typos in Readme.
- Change wording in [`DecodeError`](errors.md#blake2signer.errors.DecodeError) and [`EncodeError`](errors.md#blake2signer.errors.EncodeError) to abstract them from base 64 URL safe.
- Change `Blake2TimestampSignerBase._split_timestamp()` to decode the timestamp directly. It made some noise that after splitting one needed to decode the timestamp to actually use it.

**Security**

- Update dev dependencies, one of which (*safety*) had a security vulnerability because of a dependency (urllib3).

## 1.0.0 - 2021-02-26

**Added**

- Add a logo and icons for the project (many thanks to [NoonSleeper](https://gitlab.com/noonsleeper)).
- Add index to readme.
- Add again `flake8-annotations-complexity` since it now works in Python 3.9+.

**Changed**

- Updated dependencies.
- Use debian-based images in CI to run tests, preventing package building wreckage and improving run time (there's no need to build given most packages publish a wheel artifact).

## 0.5.1 - 2020-11-08

**Fixed**

- The idea of `66ebeff` was to accept the `hasher` parameter also as string, but the implementation and type hints were wrong. Fixed it and added corresponding tests (mental note: avoid releasing new versions at Saturday midnight).

## 0.5.0 - 2020-11-07

**Removed**

- Remove `flake8-annotations-complexity` because it is failing in Python 3.9 (there's a bug report already filled for this, and a new release should come soon).

**Added**

- Create jobs to test this lib under different Python versions.
- Add usage examples in classes docstrings.

**Changed**

- Renamed enum `Hashers_` to [`HasherChoice`](hashers.md#blake2signer.hashers.HasherChoice) and subclass it from string.
- Update dev dependencies.

**Fixed**

- Bring back Python 3.7 compatibility by removing the use of TypedDict which was unneeded.

## 0.4.0 - 2020-10-11

**Added**

- Create new parameter to set compression level in [`dumps`](signers.md#blake2signer.signers.Blake2SerializerSigner.dumps) for [`Blake2SerializerSigner`](signers.md#blake2signer.signers.Blake2SerializerSigner).
- When compressing, check if there's a benefit to it and if not skip it in [`dumps`](signers.md#blake2signer.signers.Blake2SerializerSigner.dumps) for [`Blake2SerializerSigner`](signers.md#blake2signer.signers.Blake2SerializerSigner).

**Changed**

- The signature is base64 encoded.
- The timestamp is base64 encoded.
- The salt is generated and used as base64 data to avoid needing to decode it when checking the signature.
- Use a symbol to separate composite signature from timestamp and data.
- Verify the signature before decoding.
- `Blake2Serializer` was renamed to [`Blake2SerializerSigner`](signers.md#blake2signer.signers.Blake2SerializerSigner) because of reasons.
- Derive key from `secret` and `person` in all classes.
- Force bytes in all inputs.
- Set minimum digest size of 16 (was 8).
- Always concatenate personalisation value with the class name to prevent signed data misuse.
- Rename `person` parameter to `personalisation`.
- Rename `key` parameter to `secret`.
- Some other minor changes regarding public/private API so that the only public methods are `sign`/`unsign` and `loads`/`dumps`.
- Refactor exceptions to make them make sense and be more usable.
- Improve docstrings descriptions and properly document exceptions.
- Refactor classes into abstracts and mixins so that end users can create their own implementations easily.
- Change compression flag to a dot.

## 0.3.0 - 2020-10-05

**Added**

- Initial release as a package.

**Changed**

- Use compact JSON encoding in `Blake2Serializer` class.
- Change `Blake2Serializer` interface from sign/unsign to dumps/loads.
- Move compression to dumps and mark it in the stream (this seems to prevent zip bombs).
- Force inputs as bytes.

## 0.2.0 - 2020-09-15

**Changed**

- Change composition order because it's easier to work with positive slices, and it's kinda a convention to have salt at the beginning rather than at the end (incentive from [a Twitter thread](https://twitter.com/HacKanCuBa/status/1305611525344956416)).

## 0.1.2 - 2020-09-14

**Added**

- Add basic tests (run with `python -m unittest blake2signer` or your preferred runner).

**Fixed**

- Fix digest and key size check.

## 0.1.1 - 2020-09-13

**Added**

- Derive `person` in `Signer` class to allow arbitrarily long strings.

**Changed**

- Relicense with MPL 2.0.

## 0.1.0 - 2020-09-12

**Added**

- Initial release as a [Gist](https://gist.github.com/HacKanCuBa/b93864a1ed41746b3d75f80eb09de109).
