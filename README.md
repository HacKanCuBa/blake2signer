[![Pipeline Status](https://img.shields.io/gitlab/pipeline/hackancuba/blake2signer/develop?style=plastic)](https://gitlab.com/hackancuba/blake2signer/-/pipelines?page=1&scope=all&ref=develop)
[![Coverage Report](https://img.shields.io/gitlab/coverage/hackancuba/blake2signer/develop?style=plastic)](https://gitlab.com/hackancuba/blake2signer/-/commits/develop)
[![PyPI Version](https://img.shields.io/pypi/v/blake2signer?color=light%20green&style=plastic)](https://pypi.org/project/blake2signer)
[![PyPI Python Versions](https://img.shields.io/pypi/pyversions/blake2signer?color=light%20green&style=plastic)](https://pypi.org/project/blake2signer)
[![License](https://img.shields.io/pypi/l/blake2signer?color=light%20green&style=plastic)](https://gitlab.com/hackancuba/blake2signer/-/blob/main/LICENSE)
[![Follow Me on Twitter](https://img.shields.io/twitter/follow/hackancuba?color=light%20green&style=plastic)](https://twitter.com/hackancuba)

# ![Logo](https://assets.gitlab-static.net/uploads/-/system/project/avatar/21560006/icon_d_dark.png?width=40) Blake2Signer

The goal of this project is to provide a simple and straightforward way to securely sign data using [BLAKE in keyed hashing mode](https://docs.python.org/3/library/hashlib.html#keyed-hashing).

## Why would I need to use it?

* To sign data that needs to be sent through an untrusted channel, like signing a cookie with user data and providing it to the user, so the user can identify themselves with the rest of the system safely.
* To save database lookups by checking signed data, like an account activation or password reset link where you can sign the user id and then verify it securely without using a database.
* To prevent data tampering, like signing some value that goes in a form hidden field such as the user type (admin or regular) so that the user can't trick the value.
* To easily express intent when signing data, like sharing a single secret key between signers to simplify app configuration and use the `personalisation` parameter to prevent signed data misuse.

In short, **never trust** user input, **always verify**. This module helps you do that.

## Why would I want to use it?

Because it is a relatively *small* (around 900 logical lines of code, core around 400), *simple* (the public API has only a couple of methods) yet very *customizable* and *fast* data signer. My idea is to keep it as uncomplicated as possible without much room to become a *footgun*. All *defaults are very sane* (secure) and everything *just works* out of the box.

There are much better packages for other or more general use cases so if you feel this doesn't satisfy your needs please [leave a feature request](https://gitlab.com/hackancuba/blake2signer/-/issues) or consider using [itsdangerous](https://itsdangerous.palletsprojects.com), [Django's signer](https://docs.djangoproject.com/en/dev/topics/signing), [pypaseto](https://github.com/rlittlefield/pypaseto), [pyjwt](https://github.com/jpadilla/pyjwt) or others like those.

## Goals

* Be safe and secure.
* Be simple and straightforward.
* Follow [semver](https://semver.org/).
* Be always typed.
* No dependencies (besides dev).
* 100% coverage.

### Secondary goals

* If possible, maintain current active Python versions (3.7+).

## Installing

This package is hosted on [PyPi](https://pypi.org/project/blake2signer) so just:

* `python3 -m pip install blake2signer`
* `poetry add blake2signer`
* `pipenv install blake2signer`

You can check the [releases' page](https://gitlab.com/hackancuba/blake2signer/-/releases) for package hashes and signatures.

Note: if you want to use BLAKE3, you need to install the [`blake3`](https://pypi.org/project/blake3/) package, until it arrives to core (which may or may not happen). Alternatively, you can install this package with extras:

* `python3 -m pip install blake2signer[blake3]`
* `poetry add blake2signer[blake3]`
* `pipenv install blake2signer[blake3]`

### Requirements

Only Python is required, this module doesn't have dependencies besides those used for development, and the optional `blake3`.

Versions currently tested (check the [pipelines](https://gitlab.com/hackancuba/blake2signer/-/pipelines)):

* CPython 3.7
* CPython 3.8
* CPython 3.9
* CPython 3.10
* CPython 3.11rc
* [PyPy](https://www.pypy.org) 3.7
    * If you are contributing to this project under PyPy, [read the contrib notes first](CONTRIB.md#working-under-pypy).
* [PyPy](https://www.pypy.org) 3.8
    * If you are contributing to this project under PyPy, [read the contrib notes first](CONTRIB.md#working-under-pypy).
* [Stackless](https://github.com/stackless-dev/stackless/wiki) 3.7
  * If you are contributing to this project under Stackless, [read the contrib notes first](CONTRIB.md#working-under-stackless).
* [Stackless](https://github.com/stackless-dev/stackless/wiki) 3.8
  * If you are contributing to this project under Stackless, [read the contrib notes first](CONTRIB.md#working-under-stackless).

## Tl; Dr Example

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
except errors.SignedDataError:  # See more about errors in the docs
    # Can't trust on given data
    unsigned = {}

print(unsigned)  # {'user_id': 1, 'is_admin': True, 'username': 'hackan'}
```

Find more [details](https://blake2signer.hackan.net/en/stable/details) and [examples](https://blake2signer.hackan.net/en/stable/examples) in the docs.

> Tip: all modules, classes, methods and functions are documented so don't doubt asking for `help()`.

## Signers

This module provides three signer classes:

* **Blake2SerializerSigner**: a signer class that handles data serialization, compression and encoding along with salted signing and salted timestamped signing. Its public methods are `dumps`, `loads`, `dumps_parts` and `loads_parts`, and `dump` and `load` for files.
* **Blake2Signer**: a signer class that simply salts, signs and verifies signed data as bytes or string. Its public methods are `sign`, `unsign`, `sign_parts` and `unsign_parts`.
* **Blake2TimestampSigner**: a signer class that simply salts, signs and verifies signed timestamped data as bytes or string. Its public methods are `sign`, `unsign`, `sign_parts` and `unsign_parts`.

**You should generally go for Blake2SerializerSigner**, given that it's the most versatile of the three, unless you need to deal with plain bytes or string. Check [details about signers](https://blake2signer.hackan.net/en/stable/details) and [usage examples](https://blake2signer.hackan.net/en/stable/examples) to learn more.

## Documentation

Check out this [project docs online](https://blake2signer.hackan.net) or locally with `inv docs`. Alternatively, build them locally using `inv docs --build`.

## Notice

I'm not a cryptoexpert, so *this project needs a security review*. If you are one and can do it, please [contact me](https://hackan.net).

## License

**Blake2Signer** is made by [HacKan](https://hackan.net) under MPL v2.0. You are free to use, share, modify and share modifications under the terms of that [license](LICENSE).  Derived works may link back to the canonical repository: `https://gitlab.com/hackancuba/blake2signer`.

    Copyright (C) 2020, 2021, 2022 HacKan (https://hackan.net)
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at https://mozilla.org/MPL/2.0/.

----

[![CC BY-SA 4.0](https://i.creativecommons.org/l/by-sa/4.0/80x15.png)](https://creativecommons.org/licenses/by-sa/4.0/) *Blake2Signer icons* by [NoonSleeper](https://gitlab.com/noonsleeper) are licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/). You are free to use, share, modify and share modifications under the terms of that [license](https://creativecommons.org/licenses/by-sa/4.0/). They were based on *Blake2Signer logo* by [HacKan](https://hackan.net) which was based on [this sword](https://thenounproject.com/term/samurai-sword/2044449/) by *Hamza Wahbi* and [this signature](https://thenounproject.com/term/sign/184638/) by *Nick Bluth*, both licensed under [CC BY 3.0](https://creativecommons.org/licenses/by/3.0/), and inspired by [It's dangerous logo](https://itsdangerous.palletsprojects.com/en/1.1.x/_images/itsdangerous-logo.png).

Check them out in the [icons](https://gitlab.com/hackancuba/blake2signer/-/blob/develop/icons) subdir.
