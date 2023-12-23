# Signatures

*All release tags are signed, and release packages are also signed. Always check signatures prior using this software.*

## Details

Until v2.5.0, all [tags](https://gitlab.com/hackancuba/blake2signer/-/tags) and [release packages](https://gitlab.com/hackancuba/blake2signer/-/releases) (repo bundles, python packages, etc.) are signed with *both* [GPG](https://www.gnupg.org) and [minsign](https://jedisct1.github.io/minisign/). Afterward, **only minisign** is used, so [gpg is finally deprecated](https://gist.github.com/HacKanCuBa/afe0073fe35fddf01642220acd4cde17).

However, using minisign is not immediately easy: the lack of integrations makes it a bit tedious, but it is worth it.

For example, given that there is no standard in git for signing with other than GPG (actually, OpenPGP), and that minisign is relatively young, the solution was to use [git notes](https://git-scm.com/docs/git-notes) to store the minisign signature. So, git tag objects are signed with minisign, and the signature is stored as a git note for that tag.

Additionally, since minisign signatures are wonderfully compact, I decided to include some extra information (metadata) as a [*trusted comment*](https://jedisct1.github.io/minisign/#trusted-comments) (a comment that is also signed, and thus it is trusted), such as the signature timestamp, the thing being signed (git object hash or file name), the public key used for signing (which is also wonderfully compact), and the signer's email address.

### Verifying signatures with minisign

!!! tip "Tl;Dr"
    Use `inv verify-tag <tag name>` to verify a git tag, and `inv verify-file <file name>` to verify a signed file.

To verify a git tag signature with minisign, you need to extract the signature into a file for minisign to check it. This process is simplified using the `git-minising-verify.sh` script from the [git-minisign](https://gitlab.com/hackancuba/git-minisign) project, which is included in this project's repo. Run: `./git-minisign/sh/git-minisign-verify.sh -T <tag name>`, or alternatively `inv verify-tag <tag name>`.

To verify a file signature, run `minisign -Vm <file>`, where `file` is the file you want to verify, which must be accompanied by the signature file with extension `.minisig` (in the same directory).  
The public key file used to sign is in this project's repo as `minisign.pub`. If you are checking a signature outside the repo's directory, point minisign to the public key file: `minisign -Vm <file> -p /path/to/blake2signer/minisign.pub`. Alternatively, use the public key value directly `minisign -Vm <file> -P <pubkey>`.

Current public key: [`RWRcT0IUOJ7kj6AFLyI3pHmT6dhr+WN8C2FR6HguMmEK0MnsSImqSmjg`](https://gist.github.com/HacKanCuBa/9dd1599036e026c34bd57c8444b38bd8).

### Verifying signatures with GPG

!!! tip "Tl;Dr"
    Use `git tag --verify <tag name>` to verify a git tag, and `gpg --verify <signature file>` to verify a signed file.

To verify a git tag signature with GPG, given that it is integrated into git, just run `git tag --verify <tag name>`.

To verify a file signature, run `gpg --verify <signature file>`, where `signature file` may have an extension such as `.sig` or `.asc`. Make sure that the file in question, and the signature file, are in the same directory.

Current public key: [`5D05EA4EA22F4142A0FEC764292D1CD6560BEABA`](https://keys.openpgp.org/search?q=5D05EA4EA22F4142A0FEC764292D1CD6560BEABA).
