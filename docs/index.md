# Blake2Signer

![Blake2Signer](img/title.svg)

The goal of this project is to provide a simple and straightforward way to securely sign data using [BLAKE2 in keyed hashing mode](https://docs.python.org/3/library/hashlib.html#blake2).

## Why would I need to use it?

??? example "To sign data that needs to be sent through an untrusted channel"
    When a user logs into your system, you may want to provide that user a cookie so that every operation in the system can know that they are logged in. However, you must sign that cookie, otherwise an attacker may change its value to trick the system into thinking they are logged in, or may likewise impersonate another user. This is a common scenario where the server needs to provide a value, and then read it back from the user. With this package you can sign said value and verify the signature when read so that you know it wasn't tampered with.

??? example "To save database lookups by checking signed data"
    When you need to activate a user account or generate a password reset you can sign the account id and send a link to the user, and then you can verify it by unsigning it: this saves generating a one-time token or other similar processes that requires database lookups and write operations.

??? example "To easily express intent when signing data"
    When you need to sign different data in your app, you can create different signers using a single secret (simplified app configuration): just set the `personalisation` value of each signer uniquely, as shown in the [examples](examples.md). This ensures that a value signed by a signer can't be unsigned by another signer: i.e. a malicious user can't use their signed id value for account reset to upgrade their account plan.

??? example "To prevent data tampering"
    When you need to store some value in a form but then need to act upon it, i.e. indicating if a user is an admin or regular user in a hidden field, then you must sign said value to prevent a malicious user tampering it.

In short, **never trust** user input, **always verify**. This module helps you do that.

## Why would I want to use it?

Because it is a relatively *small* (around 700 logical lines of code), *[simple](details.md)* (the public API has only a couple of methods) yet very *[customizable](details.md#encoders-serializers-and-compressors)* and *[fast](comparison.md#performance-comparison)* data signer. My idea is to keep it as uncomplicated as possible without much room to become a *footgun*. All *defaults are very sane* (secure) and everything *just works* out of the box.

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

You can check the [releases page](https://gitlab.com/hackancuba/blake2signer/-/releases) for package hashes and signatures.

### Requirements

!!! info
    Only Python is required, this module doesn't have dependencies besides those used for development.

Versions currently tested (check the [pipelines](https://gitlab.com/hackancuba/blake2signer/-/pipelines)):

* Python 3.7
* Python 3.8
* Python 3.9
* Python 3.10rc

## Documentation

These docs are generously hosted by [ReadTheDocs](https://readthedocs.org). Check the [project page](https://readthedocs.org/projects/blake2signer) to know more and see different versions of these docs.

## Notice

I'm not a cryptoexpert, so *this project needs a security review*. If you are one and can do it, please [contact me](https://hackan.net).

## License

**Blake2Signer** is made by [HacKan](https://hackan.net) under MPL v2.0. You are free to use, share, modify and share modifications under the terms of that [license](https://gitlab.com/hackancuba/blake2signer/-/blob/bb95e04c7ff3eb73aa0d923898f5eff5abad9768/LICENSE).  Derived works may link back to the canonical repository: `https://gitlab.com/hackancuba/blake2signer`.

    Copyright (C) 2020, 2021 HacKan (https://hackan.net)
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at https://mozilla.org/MPL/2.0/.

----

[![CC BY-SA 4.0](https://i.creativecommons.org/l/by-sa/4.0/80x15.png)](https://creativecommons.org/licenses/by-sa/4.0/) *[Blake2Signer icons](https://gitlab.com/hackancuba/blake2signer/-/blob/main/icons)* by [NoonSleeper](https://gitlab.com/noonsleeper) are licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/). You are free to use, share, modify and share modifications under the terms of that [license](https://creativecommons.org/licenses/by-sa/4.0/). They were based on *Blake2Signer logo* by [HacKan](https://hackan.net) which was based on [this sword](https://thenounproject.com/term/samurai-sword/2044449/) by *Hamza Wahbi* and [this signature](https://thenounproject.com/term/sign/184638/) by *Nick Bluth*, both licensed under [CC BY 3.0](https://creativecommons.org/licenses/by/3.0/), and inspired by [It's dangerous logo](https://itsdangerous.palletsprojects.com/en/1.1.x/_images/itsdangerous-logo.png).  
Check them out in the [icons](https://gitlab.com/hackancuba/blake2signer/-/blob/main/icons) subdir.

[![CC BY-SA 4.0](https://i.creativecommons.org/l/by-sa/4.0/80x15.png)](https://creativecommons.org/licenses/by-sa/4.0/) *[Blake2Signer with Logo](img/title.svg)* by [Erus](https://gitlab.com/erudin) is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/). You are free to use, share, modify and share modifications under the terms of that [license](https://creativecommons.org/licenses/by-sa/4.0/). It uses OFL licensed [Bilbo font](https://fontesk.com/bilbo-font).
