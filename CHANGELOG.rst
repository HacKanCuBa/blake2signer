1.1.0 - 2021-04-15
==================

Added
-----

- Add new `force_compression` parameter in `Blake2SerializerSigner.dumps()` to expose existing capability to force data compression.

Changed
-------

- Change execution order of steps to publish a package in Contrib, to allow room for fixes after publishing to testpypi.

- Reworded and fixed some typos in Readme.

- Change wording in DecodeError and EncodeError to abstract them from base 64 URL safe.

- Change `Blake2TimestampSignerBase._split_timestamp()` to decode the timestamp directly. It made some noise that after splitting one needed to decode the timestamp to actually use it.

Security
--------

- Update dev dependencies, one of which (*safety*) had a security vulnerability because of a dependency (urllib3).

1.0.0 - 2021-02-26
==================

Added
-----

- Add a logo and icons for the project (many thanks to NoonSleeper).
- Add index to readme.
- Add again flake8-annotations-complexity since it now works in Python 3.9+.

Changed
-------

- Updated dependencies.
- Use debian-based images in CI to run tests, prventing package building wreckage and improving run time (there's no need to build given most packages publish a wheel artifact).

0.5.1 - 2020-11-08
==================

Fixed
-----

- The idea of `66ebeff` was to accept the `hasher` parameter also as string, but the implementation and type hints were wrong. Fixed it and added corresponding tests (mental note: avoid releasing new versions at Saturday midnight).

0.5.0 - 2020-11-07
==================

Removed
-------

- Remove `flake8-annotations-complexity` because it is failing in Python 3.9 (there's a bug report already filled for this and a new release should come soon).

Added
-----

- Create jobs to tests this lib under different Python versions.
- Add usage examples in classes docstrings.

Changed
-------

- Renamed enum `Hashers_` to `HasherChoice` and subclass it from string.
- Update dev dependencies.

Fixed
-----

- Bring back Python 3.7 compatibility by removing the use of TypedDict which was unneeded.

0.4.0 - 2020-10-11
==================

Added
-----

- Create new parameter to set compression level in `dumps` for `Blake2SerializerSigner`.
- When compressing check if there's a benefit to it and if not skip it in `dumps` for `Blake2SerializerSigner`.

Changed
-------

- The signature is base64 encoded.
- The timestamp is base64 encoded.
- The salt is generated and used as base64 data to avoid needing to decode it when checking the signature.
- Use a symbol to separate composite signature from timestamp and data.
- Verify the signature before decoding.
- Blake2Serializer was renamed to Blake2SerializerSigner because of reasons.
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

0.3.0 - 2020-10-05
==================

Added
-----

- Initial release as a package.

Changed
-------

- Use compact JSON encoding in `Blake2Serializer` class.
- Change `Blake2Serializer` interface from sign/unsign to dumps/loads.
- Move compression to dumps and mark it in the stream (this seems to prevent zip bombs).
- Force inputs as bytes.

0.2.0 - 2020-09-15
==================

Changed
-------

- Change composition order because its easier to work with positive slices and it's kinda a convention to have salt at the beginning rather than at the end (incentive from `a Twitter thread <https://twitter.com/HacKanCuBa/status/1305611525344956416>`_).

0.1.2 - 2020-09-14
==================

Added
-----

- Add basic tests (run with `python -m unittest blake2signer` or your preferred runner).

Fixed
-----

- Fix digest and key size check.

0.1.1 - 2020-09-13
==================

Added
-----

- Derive `person` in `Signer` class to allow arbitrarily long strings.

Changed
-------

- Relicense with MPL 2.0.

0.1.0 - 2020-09-12
==================

Added
-----

- Initial release as a `Gist <https://gist.github.com/HacKanCuBa/b93864a1ed41746b3d75f80eb09de109>`_.
