# Security

This project takes security very seriously. If you ever find a vulnerability, please [get in touch](https://hackan.net) ASAP and/or [open an issue](https://gitlab.com/hackancuba/blake2signer/-/issues) unless disclosure is harmful.

## Improving security

With the goal of keeping this project secure, several measures are taken:

* Good test coverage to prevent bugs.
* Code fuzzed to uncover unexpected bugs.
* Static typing to prevent type-related bugs.
* Tags, releases and packages are always signed.
* No external dependencies to diminish attack surface and risk.
* Safe defaults and secure minimums enforced for sensitive values.
* Analysis of (dev) dependencies for known vulnerabilities using [safety](https://pyup.io/safety) and [trivy](https://aquasecurity.github.io/trivy/).
* Static analysis of code for common pitfalls and potential vulnerabilities using [bandit](https://bandit.readthedocs.io/en/latest).
* Build reproducibility thanks to [poetry](https://python-poetry.org/): trusted code -> trusted package (although [this may not be too important](https://blog.cmpxchg8b.com/2020/07/you-dont-need-reproducible-builds.html)).

### Code fuzzing

I wrote a fuzzing helper using [pythonfuzz](https://gitlab.com/gitlab-org/security-products/analyzers/fuzzers/pythonfuzz), check the [fuzz module](https://gitlab.com/hackancuba/blake2signer/-/blob/develop/fuzz.py). I fuzzed each signer for over 48hs without finding any issue.

!!! question "Continuous fuzzing wanted"
    Fuzzing truly benefits a project when is run continuously, but I can't currently pay for a VPS for this, so I'm looking for ideas on this matter.

## External security review

!!! warning "Expert wanted"
    This project hasn't been externally audited yet, so *this project needs a security review*. If you are an expert and can do it, please [contact me](https://hackan.net). The results of said review will be published here.
