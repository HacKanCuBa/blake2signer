# Errors

All exceptions raised by this lib are subclassed from `SignerError`. Exceptions in this lib are somewhat verbose so debugging or understanding what failed becomes easier, as it can be appreciated in the tree below.

!!! bug "Not a subclass of `SignerError`"
    If a raised exception is not a subclass of `SignerError`, then something very unexpected happened: please [fill a bug report](https://gitlab.com/hackancuba/blake2signer/-/issues/new).  
    Except for a [`RuntimeError` that will happen in ~2106-02-07](https://gitlab.com/hackancuba/blake2signer/-/blob/fcc2588939895c428d7b3420fbddaab62d864b88/blake2signer/bases.py#L462-465), if this library is unmaintained by then.

For example, all errors related to signature validation inherit from `SignatureError`, which in turn inherits from `SignedDataError`. This means that you can safely catch the latter when dealing with signed data that needs to be verified without worrying on masking other errors such as those produced on class instantiation.

You can catch exceptions at the level you prefer, or i.e. broad catch them and then log them according to the exception.

```python
"""Catching errors."""

from datetime import timedelta

from blake2signer import Blake2SerializerSigner
from blake2signer import errors

secret = b'there is no encryption here'
data = [102, 117, 99, 107, 32, 116, 104, 101, 32, 112, 111, 108, 105, 99, 101]
max_age = timedelta(hours=1)

signer = Blake2SerializerSigner(secret, max_age=max_age)
try:
    signed = signer.dumps(data)
except errors.SerializationError:
    print('Data could not be serialized')
except errors.CompressionError:
    print('Data could not be compressed')
except errors.EncodeError:
    print('Data could not be encoded')
except errors.UnsignedDataError:
    # Unreachable if all above exceptions are caught
    print('Data could not be processed somehow')
except errors.DataError:
    # Unreachable if all above exceptions are caught
    print('Unknown error while processing data')
except errors.SignerError:
    # Unreachable if all above exceptions are caught
    print('Unknown error')

try:
    unsigned = signer.loads(signed)
except errors.ConversionError:
    print('Signed data could not be converted to bytes, so data can not be processed')
except errors.ExpiredSignatureError as exc:
    print('Signature is valid but expired on', (exc.timestamp + max_age).isoformat())
except errors.InvalidSignatureError:
    print('The signature is not valid, so data can not be trusted!')
except errors.SignatureError:
    print('The signature is not valid because of its format, so data can not be trusted!')
except errors.DecodeError:
    print('It was not possible to decode data even when signature was valid, what could have happened?')
except errors.DecompressionError:
    print('It was not possible to decompress data even when signature was valid, what could have happened?')
except errors.UnserializationError:
    print('It was not possible to unserialize data even when signature was valid, what could have happened?')
except errors.SignedDataError:
    # Unreachable if all above exceptions are caught
    print('The signature is not valid and/or some part of the unsigning process failed, so data can not be trusted!')
except errors.DataError:
    # Unreachable if all above exceptions are caught
    print('Unknown error while processing data')
except errors.SignerError:
    # Unreachable if all above exceptions are caught
    print('Unknown error')
else:
    # Signature and all is good
    print(unsigned)  # [102, 117, 99, 107, 32, 116, 104, 101, 32, 112, 111, 108, 105, 99, 101]
```

!!! question "Impossible errors?"
    Some exceptions should normally never happen such as `DecodeError`, `DecompressionError` and `UnserializationError`. They exist because they are theoretically possible, and achievable by tricking the signer bypassing in-place safeguards (see [the tests](https://gitlab.com/hackancuba/blake2signer/-/blob/bdc9ca18394cedaebc7c35071435e15b515a8e14/blake2signer/tests/test_signers.py#L1004-1046) for examples).

::: blake2signer.errors
