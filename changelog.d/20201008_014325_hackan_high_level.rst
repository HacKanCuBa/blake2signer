Changed
-------

- Derive key from `secret` and `person` in all classes.
- Force bytes in all inputs.
- Set minimum digest size of 16 (was 8).
- Always concatenate personalisation value with the class name to prevent signed data misuse.
- Rename `person` parameter to `personalisation`.
- Rename `key` parameter to `secret`.
- Some other minor changes regarding public/private API so that the only public methods are `sign`/`unsign` and `loads`/`dumps`.
