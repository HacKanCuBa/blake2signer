# Performance

This section discusses internals of this lib and performance tweaks that can help your app run smoother with it. Check the [performance comparison with other libs](comparison.md#performance-comparison) in its page.

## Class instantiation

During class instantiation, both the `secret` and `personalisation` values are derived, and every parameter is checked to be in certain bounds; therefore there is a performance impact similar to sign a relatively small payload. It is twice as significant when instantiating *Blake2SerializerSigner* than the other signers. So, this creates an interesting optimization possibility: to cache the class instantiation.

!!! warning
    If the instantiation only occurs once, then using a cache won't make a difference since the first hit is always needed to produce it. Test your implementation to make sure it is making a positive difference.

There is [an example](examples.md#real-use-case) of this where the standard library `functools.cached_property` is used to cache the class instantiation. Another option is to use [`functools.lru_cache`](https://docs.python.org/3.8/library/functools.html?highlight=lru_cache#functools.lru_cache). I tested caching the instantiation vs not doing it, and it takes ~98% less time! That's a huge performance bonus, particularly when this is done at least once per request for a web app, considering the cache lives across requests.

!!! note
    The standard deviation presented on each evaluation should be at least two orders of magnitude lower than the mean for appropriate results.

??? example "Testing the performance of caching class instantiation code"
    ```python
    """Testing the performance of caching class instantiation."""

    from functools import lru_cache

    from blake2signer import Blake2SerializerSigner
    from blake2signer import Blake2Signer


    def format_time(
            dt: float,
            *,
            unit: str = None,
            precision: int = 3,
    ) -> str:
        """Format time (copied from timeit lib)."""
        units = {'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0}

        if unit:
            scale = units[unit]
        else:
            scales = [(scale, unit) for unit, scale in units.items()]
            scales.sort(reverse=True)
            for scale, unit in scales:
                if dt >= scale:
                    break

        return '%.*g %s' % (precision, dt / scale, unit)


    def print_row(name: str, value: float, ok: bool, baseline: float):
        """Print a table row."""
        rel = int(value * 100 / baseline) - 100
        perf_diff = '' if rel == 0 else ('(slower than baseline)' if rel > 0 else '(faster than baseline)')
        print(
            name.ljust(40),
            '|',
            format_time(value).rjust(13),
            '|',
            ('√' if ok else '⚠').center(7),
            '|',
            f'{rel}%'.rjust(4) if value != baseline else 'baseline',
            perf_diff,
        )


    def test_b2s_no_cache(secret):
        """Test Blake2Signer without caching instantiation."""
        signer = Blake2Signer(secret)


    @lru_cache
    def b2s_cached(secret):
        """Cache Blake2Signer instantiation."""
        return Blake2Signer(secret)


    def test_b2s_cache(secret):
        """Test Blake2Signer caching instantiation."""
        signer = b2s_cached(secret)


    def test_b2ss_no_cache(secret):
        """Test Blake2SerializerSigner without caching instantiation."""
        signer = Blake2SerializerSigner(secret)


    @lru_cache
    def b2ss_cached(secret):
        """Cache Blake2SerializerSigner instantiation."""
        return Blake2SerializerSigner(secret)


    def test_b2ss_cache(secret):
        """Test Blake2SerializerSigner caching instantiation."""
        signer = b2ss_cached(secret)


    s = b'secret' * 3
    signers = {}
    serializers = {}

    # Using ipython:
    print('Test Blake2Signer without caching instantiation')
    signers['Blake2Signer w/o caching'] = %timeit -o -r 10 test_b2s_no_cache(s)

    print('Test Blake2Signer caching instantiation')
    signers['Blake2Signer w/ caching'] = %timeit -o -r 10 test_b2s_cache(s)

    print('Test Blake2SerializerSigner without caching instantiation')
    serializers['Blake2SerializerSigner w/o caching'] = %timeit -o -r 10 test_b2ss_no_cache(s)

    print('Test Blake2SerializerSigner caching instantiation')
    serializers['Blake2SerializerSigner w/ caching'] = %timeit -o -r 10 test_b2ss_cache(s)

    print()
    print('Signer'.ljust(40), '| Best Abs Time | Measure | Comparison')
    print('-' * 40, '|', '-' * 13, '|', '-' * 7 ,'|', '-' * 27)
    baseline = signers['Blake2Signer w/o caching'].best
    for timing in signers:
        ok = (signers[timing].best / signers[timing].stdev) > 60
        print_row(timing, signers[timing].best, ok, baseline)

    print()
    print('Serializer'.ljust(40), '| Best Abs Time | Measure | Comparison')
    print('-' * 40, '|', '-' * 13, '|', '-' * 7 ,'|', '-' * 27)
    baseline = serializers['Blake2SerializerSigner w/o caching'].best
    for timing in serializers:
        ok = (serializers[timing].best / serializers[timing].stdev) > 60
        print_row(timing, serializers[timing].best, ok, baseline)
    ```

!!! note
    `Blake2TimestampSigner` is equivalent in its instantiation to `Blake2Signer`, so it is not tested here.

## Preferring bytes over string

Internally, all signers need to work with bytes because the hashers have this requirement. For convenience both bytes and string are accepted as input, but a conversion happens behind the curtains. This conversion has an impact in performance, and it can be somewhat significant in the long run: when profiling a sign or unsign cycle, one can see that most of the time is spent calculating the hash (this is unavoidable), but a good portion of the rest of the time is spent encoding strings!

??? example "Profiling the signer"
    ```python
    """Profiling the signer."""

    from blake2signer import Blake2Signer

    secret = b'secret' * 3
    data = b'data' * 10_000_000  # Has to be very large to see the numbers
    data_s = data.decode()

    signer = Blake2Signer(secret)

    # Note that the timing values per se are not important, but their order is.

    # Using ipython:
    %prun -l 4 signer.sign(data)
    # 33 function calls in 0.114 seconds
    #
    # Ordered by: internal time List reduced from 24 to 4 due to restriction <4>
    #
    # ncalls tottime percall cumtime percall filename:lineno(function)
    # 1 0.093 0.093 0.093 0.093 bases.py:406(_signify)
    # 1 0.020 0.020 0.020 0.020 bases.py:379(_compose)
    # 1 0.002 0.002 0.114 0.114 <string>:1(<module>)
    # 1 0.000 0.000 0.114 0.114 {built-in method builtins.exec}

    %prun -l 4 signer.sign(data_s)
    # 35 function calls in 0.137 seconds
    #
    # Ordered by: internal time List reduced from 25 to 4 due to restriction <4>
    #
    # ncalls tottime percall cumtime percall filename:lineno(function)
    # 1 0.070 0.070 0.070 0.070 bases.py:406(_signify)
    # 1 0.045 0.045 0.045 0.045 {method 'encode' of 'str' objects}  # <<<< !!!
    # 1 0.019 0.019 0.019 0.019 bases.py:379(_compose)
    # 1 0.003 0.003 0.137 0.137 <string>:1(<module>)
    ```

Therefore, you should prefer using bytes rather than strings. However, if you can't avoid it, it's fine: don't go crazy thinking how to do it! The benefit is marginal at best for large payloads, and almost negligible for small ones. So this is just to make the point that, in the long run, if you can use bytes then that should be preferred, otherwise it's fine.

## Choosing the right signer

This class offers three signers, and one of them is additionally a serializer meaning it can serialize any python object before signing it. You should be aware that this has a huge impact in performance and that serializing objects can be expensive.

!!! note
    The standard deviation presented on each evaluation should be at least two orders of magnitude lower than the mean for appropriate results.

??? example "To serialize or not to serialize"
    ```python
    """To serialize or not to serialize: that is the question."""

    from blake2signer import Blake2Signer, Blake2SerializerSigner

    secret = 's' * 16
    data = 'data' * 20

    signer = Blake2Signer(secret)
    serializer_signer = Blake2SerializerSigner(secret)

    %timeit -r 10 signer.unsign(signer.sign(data))
    %timeit -r 10 serializer_signer.loads(serializer_signer.dumps(data, compress=False))
    ```

In the example above, serializing the simple string cost us twice as much as not doing it, which is pretty significant. However, if you don't know from beforehand the kind of objects you will be signing, then going for the serializer signer would be the safe bet.

## Compressing has its perks

The serializer signer class can compress the payload to make it smaller and more manageable, but this implies a big performance hit: compressing and decompressing has a cost. The class is [*somewhat smart*](examples.md#compressing-data) and checks that if the payload wasn't [compressed enough](examples.md#changing-the-compression-ratio), then it will leave it as it is, so it doesn't waste additional time during decompression for no gain. However, it needs to try and compress it first, so some time may be wasted. For incompressible data, around ~35% of time is saved if compression is disabled.

Given this, it can be beneficial if you know from beforehand whether it will be worth compressing the payload or not: you can control this using the parameters `compress`, `compression_level` and `compression_ratio` with `Blake2SerializerSigner`. Check [the examples](examples.md#compressing-data) for more information.

Generally, regular data with human-readable text is highly compressible which is why this characteristic is enabled by default, but [YMMV](https://www.urbandictionary.com/define.php?term=ymmv).

!!! note
    The standard deviation presented on each evaluation should be at least two orders of magnitude lower than the mean for appropriate results.

??? example "The cost of compression"
    ```python
    """The cost of compression."""

    from secrets import token_bytes

    from blake2signer import Blake2SerializerSigner
    from blake2signer.serializers import NullSerializer


    def format_time(
            dt: float,
            *,
            unit: str = None,
            precision: int = 3,
    ) -> str:
        """Format time (copied from timeit lib)."""
        units = {'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0}

        if unit:
            scale = units[unit]
        else:
            scales = [(scale, unit) for unit, scale in units.items()]
            scales.sort(reverse=True)
            for scale, unit in scales:
                if dt >= scale:
                    break

        return '%.*g %s' % (precision, dt / scale, unit)


    def print_row(name: str, value: float, ok: bool, baseline: float):
        """Print a table row."""
        rel = int(value * 100 / baseline) - 100
        perf_diff = '' if rel == 0 else ('(slower than baseline)' if rel > 0 else '(faster than baseline)')
        print(
            name.ljust(40),
            '|',
            format_time(value).rjust(13),
            '|',
            ('√' if ok else '⚠').center(7),
            '|',
            f'{rel}%'.rjust(4) if value != baseline else 'baseline',
            perf_diff,
        )

    secret = 'secret' * 3
    incompressible_data = token_bytes()

    signer = Blake2SerializerSigner(secret, serializer=NullSerializer)

    timings = {}

    print('With full compression')
    timings['With full compression'] = %timeit -o -r 10 signer.loads(signer.dumps(incompressible_data, force_compression=True))

    print('With smart compression')
    timings['With smart compression'] = %timeit -o -r 10 signer.loads(signer.dumps(incompressible_data, compress=True))

    print('Without compression')
    timings['Without compression'] = %timeit -o -r 10 signer.loads(signer.dumps(incompressible_data, compress=False))

    print()
    print('Timing'.ljust(40), '| Best Abs Time | Measure | Comparison')
    print('-' * 40, '|', '-' * 13, '|', '-' * 7 ,'|', '-' * 27)
    baseline = timings['With full compression'].best
    for timing in timings:
        ok = (timings[timing].best / timings[timing].stdev) > 60
        print_row(timing, timings[timing].best, ok, baseline)
    ```

## Randomness is expensive

Unfortunately, extracting cryptographically secure pseudorandom data in Python is a bit expensive, so generating a salt can take its toll. You can control [whether a salt is used or not](details.md#about-salt-and-personalisation) with the `deterministic` [class instantiation parameter](details.md#parameters). However, this performance impact may be negligible for your implementation, and [having a salt can be a positive trait](details.md#about-salt-and-personalisation).

??? example "The cost of randomness"
    ```python
    """The cost of randomness."""

    from blake2signer import Blake2Signer


    def format_time(
            dt: float,
            *,
            unit: str = None,
            precision: int = 3,
    ) -> str:
        """Format time (copied from timeit lib)."""
        units = {'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0}

        if unit:
            scale = units[unit]
        else:
            scales = [(scale, unit) for unit, scale in units.items()]
            scales.sort(reverse=True)
            for scale, unit in scales:
                if dt >= scale:
                    break

        return '%.*g %s' % (precision, dt / scale, unit)


    def print_row(name: str, value: float, ok: bool, baseline: float):
        """Print a table row."""
        rel = int(value * 100 / baseline) - 100
        perf_diff = '' if rel == 0 else ('(slower than baseline)' if rel > 0 else '(faster than baseline)')
        print(
            name.ljust(35),
            '|',
            format_time(value).rjust(13),
            '|',
            ('√' if ok else '⚠').center(7),
            '|',
            f'{rel}%'.rjust(4) if value != baseline else 'baseline',
            perf_diff,
        )

    secret = b'Protect whistleblowers!'
    regular_data = b'Free Chelsea Manning!' * 5
    large_data = regular_data * 40

    signer = Blake2Signer(secret, deterministic=False)
    deterministic_signer = Blake2Signer(secret, deterministic=True)

    for data in (regular_data, large_data):
        timings = {}

        print('Payload size:', len(data), 'bytes')
        print()

        print('Non-deterministic signature')
        timings['Non-deterministic signature'] = %timeit -o -r 10 signer.unsign(signer.sign(data))

        print('Deterministic signature')
        timings['Deterministic signature'] = %timeit -o -r 10 deterministic_signer.unsign(deterministic_signer.sign(data))

        print()
        print('Timing'.ljust(35), '| Best Abs Time | Measure | Comparison')
        print('-' * 35, '|', '-' * 13, '|', '-' * 7 ,'|', '-' * 27)
        baseline = timings['Non-deterministic signature'].best
        for timing in timings:
            ok = (timings[timing].best / timings[timing].stdev) > 60
            print_row(timing, timings[timing].best, ok, baseline)
        print()
    ```

## BLAKE versions

Different BLAKE versions and modes can perform better or worse depending on the hardware they're running on. For example, BLAKE2b is optimized for 64b platforms whereas BLAKE2s, for 8-32b platforms (read more about them in their [official site](https://blake2.net/)).

You should test your implementation to see which hasher performs better.

!!! note
    The standard deviation presented on each evaluation should be at least two orders of magnitude lower than the mean for appropriate results.

??? example "Comparing BLAKE versions"
    ```python
    """Comparing BLAKE versions."""

    from secrets import token_bytes

    from blake2signer import Blake2Signer


    def format_time(
            dt: float,
            *,
            unit: str = None,
            precision: int = 3,
    ) -> str:
        """Format time (copied from timeit lib)."""
        units = {'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0}

        if unit:
            scale = units[unit]
        else:
            scales = [(scale, unit) for unit, scale in units.items()]
            scales.sort(reverse=True)
            for scale, unit in scales:
                if dt >= scale:
                    break

        return '%.*g %s' % (precision, dt / scale, unit)


    def print_row(name: str, value: float, ok: bool, baseline: float):
        """Print a table row."""
        rel = int(value * 100 / baseline) - 100
        perf_diff = '' if rel == 0 else ('(slower than baseline)' if rel > 0 else '(faster than baseline)')
        print(
            name.ljust(20),
            '|',
            format_time(value).rjust(13),
            '|',
            ('√' if ok else '⚠').center(7),
            '|',
            f'{rel}%'.rjust(4) if value != baseline else 'baseline',
            perf_diff,
        )

    secret = b'civil disobedience is necessary'
    data = b'remember Aaron Swartz'
    large_data = data * 300
    vlarge_data = data * 1000

    for d in (data, large_data, vlarge_data):
        timings = {}
        print('Payload size:', len(d), 'bytes')

        for hasher in Blake2Signer.Hashers:
            signer = Blake2Signer(secret, hasher=hasher)
            timing = hasher.value

            print(timing)
            timings[timing] = %timeit -o -r 10 signer.unsign(signer.sign(d))

        print()
        print('Timing'.ljust(20), '| Best Abs Time | Measure | Comparison')
        print('-' * 20, '|', '-' * 13, '|', '-' * 7 ,'|', '-' * 27)
        baseline = timings['blake2b'].best
        for timing in timings:
            ok = (timings[timing].best / timings[timing].stdev) > 60
            print_row(timing, timings[timing].best, ok, baseline)
        print()
    ```
