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
