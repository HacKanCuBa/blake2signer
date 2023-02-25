# Hashers

!!! note
    If you need to use `blake3` for something, import it from this module instead of doing so directly!  
    `from blake2signer.hashers import blake3`  
    This is due to the fact that the package is optional, and it may not be installed: this module handles it properly, and will raise an exception when the function is called without the package installed, but not before.


::: blake2signer.hashers
    options:
        merge_init_into_class: true

### blake3

`blake3(data: bytes = b'', /, *, key: bytes | None = None, derive_key_context: bytes | None = None, max_threads: int = 1, usedforsecurity: bool = True)`

An incremental BLAKE3 hasher, which can accept any number of writes. The interface is similar to `hashlib.blake2b` or `hashlib.md5` from the standard library.

**Parameters:**

| Name   | Type    | Description                                                                                           | Default |
|--------|---------|-------------------------------------------------------------------------------------------------------|---------|
| `data` | `bytes` | Input bytes to hash. Setting this to non-None is equivalent to calling update on the returned hasher. | `b''`   |


**Other Parameters:**

| Name                 | Type    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Default |
|----------------------|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| `key`                | `bytes` | A 32-byte key. Setting this to non-None enables the BLAKE3 keyed hashing mode.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `None`  |
| `derive_key_context` | `bytes` | A hardcoded, globally unique, application-specific context string. Setting this to non-None enables the BLAKE3 key derivation mode. derive_key_context and key cannot be used at the same time.                                                                                                                                                                                                                                                                                                                                                                                                                                | `None`  |
| `max_threads`        | `int`   | The maximum number of threads that the implementation may use for hashing. The default value is 1, meaning single-threaded. max_threads may be any positive integer, or the value of the class attribute blake3.AUTO, which lets the implementation use as many threads as it likes. (Currently this means a number of threads equal to the number of logical CPU cores, but this is not guaranteed.) The actual number of threads used may be less than the maximum and may change over time. API-compatible reimplementations of this library may also ignore this parameter entirely, if they don't support multithreading. | `1`     |
| `usedforsecurity`    | `bool`  | Currently ignored. See the standard hashlib docs.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `True`  |
