# FAQ

## Is this project being maintained?

Yes, I'm actively maintaining it, and producing releases on a regular basis, even with new features. As a general rule, you can check the [repo activity](https://gitlab.com/hackancuba/blake2signer/activity) or the [commits graph](https://gitlab.com/hackancuba/blake2signer/-/network/develop).

## How can I do *something*?

Check the [examples](examples.md) and [details](details.md) for more information. If you still can't solve your doubt, please [open an issue](https://gitlab.com/hackancuba/blake2signer/-/issues/new).

## Why would I use this package instead of *X*?

If you are already using *X* package, then there may be little to no benefit to change it, unless there's some characteristic you are specifically looking for. However, if you are still choosing one or the other, you may want to give this package a try. Check the [comparison with other similar libs](comparison.md) for reference.

## Can I use this package in production?

Yes, it has a stable API and is ready for production. It will greatly benefit of having more time in the wild and/or an external security review. Additionally, it will always follow [semver](https://semver.org/), so rest assured that minors and patches *should not* break your application, ever. Take a peak at the [upgrade guide](upgrade.md) detailing everything related to version changes.

## Will this package support other versions of BLAKE?

Sure thing. The latest version is 3, but it hasn't made its way to the Python core yet. However, since v2.2.0 if you have the [`blake3`](https://pypi.org/project/blake3/) package installed, [you can use it](examples.md#using-blake3).

## Has this package been audited?

No, not yet. I'm [looking for it](security.md#external-security-review).

## Can I sign an email or stuff like that like with PGP?

No, you can't. This package and others like this one deals with symmetric keys and a signing mechanism known as [HMAC](https://en.wikipedia.org/wiki/HMAC). What you are looking for is a signer that deals with asymmetric keys such as [GnuPG](https://www.gnupg.org) or [minisign](https://jedisct1.github.io/minisign).

## Where can I discuss about implementation details, usage, etc.?

You are welcome at our [Matrix room](https://matrix.to/#/#blake2signer:mozilla.org) for any kind of discussion. Come by, and say hello, or request for help.  
For issues, please use the [Gitlab issue tracker](https://gitlab.com/hackancuba/blake2signer/-/issues).
