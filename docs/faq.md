# FAQ

## How can I do *something*?

Check the [examples](examples.md) and [details](details.md) for more information. If you still can't solve your doubt, please [open an issue](https://gitlab.com/hackancuba/blake2signer/-/issues/new).

## Why would I use this package instead of *X*?

If you are already using *X* package, then there may be little to no benefit to change it, unless there's some characteristic you are specifically looking for. However, if you are still choosing one or the other, you may want to give this package a try. Check the [comparison with other similar libs](comparison.md) for reference.

## Can I use this package in production?

Yes, it has a stable API and is ready for production. It will greatly benefit of having more time in the wild and/or an external security review.

## Will this package support other versions of BLAKE?

Sure thing. The latest version is 3, but it hasn't made its way to the Python core yet. There is an [excellent package](https://pypi.org/project/blake3/) available, so I'm planning to support its usage in the near future.

## Has this package been audited?

No, not yet. I'm [looking for it](security.md#external-security-review).

## Can I sign an email or stuff like that like with PGP?

No, you can't. This package and others like this one deals with symmetric keys and a signing mechanism known as [HMAC](https://en.wikipedia.org/wiki/HMAC). What you are looking for is a signer that deals with asymmetric keys such as [GnuPG](https://www.gnupg.org) or [minisign](https://jedisct1.github.io/minisign).
