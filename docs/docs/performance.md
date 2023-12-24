# Performance

This section discusses internals of this lib and performance tweaks that can help your app run smoother with it. Check the [performance comparison with other libs](comparison.md#performance-comparison) in its page.

## Class instantiation

During class instantiation, both the `secret` and `personalisation` values are derived, and every parameter is checked to be in certain bounds; therefore, there is a performance impact similar to sign a relatively small payload. It is twice as significant when instantiating [*Blake2SerializerSigner*](signers.md#blake2signer.signers.Blake2SerializerSigner) than the other signers. So, this creates an interesting optimization possibility: to cache the class instantiation.

!!! warning
    If the instantiation only occurs once, then using a cache won't make a difference since the first hit is always needed to produce it. Test your implementation to make sure it is making a positive difference.

There is [an example](examples.md#real-use-case) of this where the standard library `functools.cached_property` is used to cache the class instantiation. Another option is to use [`functools.lru_cache`](https://docs.python.org/3.8/library/functools.html?highlight=lru_cache#functools.lru_cache), but make sure that you [don't use it in a method](https://www.youtube.com/watch?v=sVjtp6tGo0g). I tested caching the instantiation vs not doing it, and it takes ~98% less time! That's a huge performance bonus, particularly when this is done at least once per request for a web app, considering the cache lives across requests.

!!! note
    The standard deviation presented on each evaluation should be at least two orders of magnitude lower than the mean for appropriate results.

??? example "Testing the performance of caching class instantiation code"
    === "Source"

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


        @lru_cache(maxsize=None)
        def b2s_cached(secret):
            """Cache Blake2Signer instantiation."""
            return Blake2Signer(secret)


        def test_b2s_cache(secret):
            """Test Blake2Signer caching instantiation."""
            signer = b2s_cached(secret)


        def test_b2ss_no_cache(secret):
            """Test Blake2SerializerSigner without caching instantiation."""
            signer = Blake2SerializerSigner(secret)


        @lru_cache(maxsize=None)
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
            # check if deviation is too big
            ok = (serializers[timing].best / serializers[timing].stdev) > 60
            print_row(timing, serializers[timing].best, ok, baseline)
        ```

    === "Output"
        ```
        Test Blake2Signer without caching instantiation
        11.3 µs ± 1.23 µs per loop (mean ± std. dev. of 10 runs, 100,000 loops each)
        Test Blake2Signer caching instantiation
        146 ns ± 3.39 ns per loop (mean ± std. dev. of 10 runs, 10,000,000 loops each)
        Test Blake2SerializerSigner without caching instantiation
        17.7 µs ± 1.02 µs per loop (mean ± std. dev. of 10 runs, 100,000 loops each)
        Test Blake2SerializerSigner caching instantiation
        145 ns ± 1.3 ns per loop (mean ± std. dev. of 10 runs, 10,000,000 loops each)
        
        Signer                                   | Best Abs Time | Measure | Comparison
        ---------------------------------------- | ------------- | ------- | ---------------------------
        Blake2Signer w/o caching                 |       10.6 us |    ⚠    | baseline (faster than baseline)
        Blake2Signer w/ caching                  |        141 ns |    ⚠    | -99% (faster than baseline)
        
        Serializer                               | Best Abs Time | Measure | Comparison
        ---------------------------------------- | ------------- | ------- | ---------------------------
        Blake2SerializerSigner w/o caching       |       16.7 us |    ⚠    | baseline 
        Blake2SerializerSigner w/ caching        |        143 ns |    √    | -100% (faster than baseline)
        ```

!!! note
    `Blake2TimestampSigner` is equivalent in its instantiation to `Blake2Signer`, so it is not tested here.

## Preferring bytes over string

Internally, all signers need to work with bytes because the hashers have this requirement. For convenience, both bytes and string are accepted as input, but a conversion happens behind the curtains. This conversion has an impact on performance, and it can be somewhat significant in the long run: when profiling a sign or unsign cycle, one can see that most of the time is spent calculating the hash (this is unavoidable), but a good portion of the rest of the time is spent encoding strings!

??? example "Profiling the signer"
    === "Source"

        ```python
        """Profiling the signer."""

        from blake2signer import Blake2Signer

        secret = b'secret' * 3
        data = b'data' * 10_000_000  # Has to be very large to easily see the numbers
        data_s = data.decode()

        signer = Blake2Signer(secret)

        # Note that the timing values per se are not important, but their order is.

        print('Profiling signing with data as bytes')
        # Using ipython:
        %prun -l 4 signer.sign(data)
        # 32 function calls in 0.101 seconds
        #
        # Ordered by: internal time
        # List reduced from 24 to 4 due to restriction <4>
        #
        # ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        #     1    0.071    0.071    0.071    0.071 blakehashers.py:195(digest)
        #     1    0.028    0.028    0.028    0.028 bases.py:396(_compose)
        #     1    0.002    0.002    0.101    0.101 <string>:1(<module>)
        #     1    0.000    0.000    0.101    0.101 {built-in method builtins.exec}
    
        print('\nProfiling signing with data as string')
        %prun -l 4 signer.sign(data_s)
        # 34 function calls in 0.132 seconds
        #
        # Ordered by: internal time
        # List reduced from 25 to 4 due to restriction <4>
        #
        # ncalls  tottime  percall  cumtime  percall filename:lineno(function)
        #     1    0.071    0.071    0.071    0.071 blakehashers.py:195(digest)
        #     1    0.029    0.029    0.029    0.029 {method 'encode' of 'str' objects}     <<<<!!!
        #     1    0.027    0.027    0.027    0.027 bases.py:396(_compose)
        #     1    0.004    0.004    0.132    0.132 <string>:1(<module>)
        ```

    === "Output"

        ```
        Profiling signing with data as bytes
                 32 function calls in 0.101 seconds

           Ordered by: internal time
           List reduced from 24 to 4 due to restriction <4>
        
           ncalls  tottime  percall  cumtime  percall filename:lineno(function)
                1    0.071    0.071    0.071    0.071 blakehashers.py:195(digest)
                1    0.028    0.028    0.028    0.028 bases.py:396(_compose)
                1    0.002    0.002    0.101    0.101 <string>:1(<module>)
                1    0.000    0.000    0.101    0.101 {built-in method builtins.exec}

        Profiling signing with data as string
                 34 function calls in 0.132 seconds
        
           Ordered by: internal time
           List reduced from 25 to 4 due to restriction <4>
        
           ncalls  tottime  percall  cumtime  percall filename:lineno(function)
                1    0.071    0.071    0.071    0.071 blakehashers.py:195(digest)
                1    0.029    0.029    0.029    0.029 {method 'encode' of 'str' objects}
                1    0.027    0.027    0.027    0.027 bases.py:396(_compose)
                1    0.004    0.004    0.132    0.132 <string>:1(<module>)
        ```

Therefore, you should prefer using bytes rather than strings. However, if you can't avoid it, it's fine: don't lose your mind thinking how to do it! The benefit is marginal at best for large payloads, and almost negligible for small ones. So this is to make the point that, in the long run, if you can use bytes, then that should be preferred; otherwise, it's fine.

### The same goes for files!

When using file-related methods, like [*Blake2SerializerSigner*](signers.md#blake2signer.signers.Blake2SerializerSigner)'s [`load`](#blake2signer.signers.Blake2SerializerSigner.load) and [`dump`](#blake2signer.signers.Blake2SerializerSigner.dump), this consideration is also pertinent.  
For both, it is convenient for the file to be opened in **binary** mode, rather than in text mode. This is to prevent a string to bytes conversion in first case, and to prevent a bytes to string conversion in the second case.

## Choosing the right signer

This class offers three signers, and one of them is additionally a serializer, meaning it can serialize any python object before signing it. You should be aware that this has a huge impact on performance and that serializing objects can be expensive.

!!! note
    The standard deviation presented on each evaluation should be at least two orders of magnitude lower than the mean for appropriate results.

??? example "To serialize or not to serialize"
    === "Source"

        ```python
        """To serialize or not to serialize: that is the question."""

        from blake2signer import Blake2Signer, Blake2SerializerSigner

        secret = 's' * 16
        data = 'data' * 20

        signer = Blake2Signer(secret)
        serializer_signer = Blake2SerializerSigner(secret)

        print('Timing signer...')
        %timeit -r 10 signer.unsign(signer.sign(data))
        print('Timing serializer signer...')
        %timeit -r 10 serializer_signer.loads(serializer_signer.dumps(data, compress=False))
        ```

    === "Output"

        ```
        Timing signer...
        10.6 µs ± 171 ns per loop (mean ± std. dev. of 10 runs, 100,000 loops each)
        Timing serializer signer...
        28.9 µs ± 2.07 µs per loop (mean ± std. dev. of 10 runs, 10,000 loops each)
        ```

In the example above, serializing the simple string costs us twice as much as not doing it, which is pretty significant. However, if you don't know from beforehand the kind of objects you will be signing, then going for the serializer signer would be the safe bet.

## Compressing has its perks

The serializer signer class can compress the payload to make it smaller and more manageable, but this implies a big performance hit: compressing and decompressing has a cost. The class is [*somewhat smart*](examples.md#compressing-data) and checks that if the payload wasn't [compressed enough](examples.md#changing-the-compression-ratio), then it will leave it as it is, so it doesn't waste additional time during decompression for no gain. However, it needs to try and compress it first, so some time may be wasted. For incompressible data, around ~35% of time is saved if compression is disabled.

Given this, it can be beneficial if you know from beforehand whether it will be worth compressing the payload or not: you can control this using the parameters `compress`, `compression_level` and `compression_ratio` with `Blake2SerializerSigner`. Check [the examples](examples.md#compressing-data) for more information.

Generally, regular data with human-readable text is highly compressible, which is why this characteristic is enabled by default, but [YMMV](https://www.urbandictionary.com/define.php?term=ymmv).

!!! note
    The standard deviation presented on each evaluation should be at least two orders of magnitude lower than the mean for appropriate results.

??? example "The cost of compression"
    === "Source"

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
            # check if deviation is too big
            ok = (timings[timing].best / timings[timing].stdev) > 60
            print_row(timing, timings[timing].best, ok, baseline)
        ```

    === "Output"

        ```
        With full compression
        28.4 µs ± 672 ns per loop (mean ± std. dev. of 10 runs, 10,000 loops each)
        With smart compression
        26.7 µs ± 722 ns per loop (mean ± std. dev. of 10 runs, 10,000 loops each)
        Without compression
        16.9 µs ± 153 ns per loop (mean ± std. dev. of 10 runs, 100,000 loops each)
        
        Timing                                   | Best Abs Time | Measure | Comparison
        ---------------------------------------- | ------------- | ------- | ---------------------------
        With full compression                    |       27.5 us |    ⚠    | baseline 
        With smart compression                   |         26 us |    ⚠    |  -6% (faster than baseline)
        Without compression                      |       16.5 us |    √    | -41% (faster than baseline)
        ```

## Randomness is expensive

Unfortunately, extracting cryptographically secure pseudorandom data in Python is a bit expensive, so generating a salt can take its toll. You can control [whether a salt is used or not](details.md#about-salt-and-personalisation) with the `deterministic` [class instantiation parameter](details.md#parameters). However, this performance impact may be negligible for your implementation, and [having a salt can be a positive trait](details.md#about-salt-and-personalisation).

??? example "The cost of randomness"
    === "Source"

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
                # check if deviation is too big
                ok = (timings[timing].best / timings[timing].stdev) > 60
                print_row(timing, timings[timing].best, ok, baseline)
            print()
        ```

    === "Output"

        ```
        Payload size: 105 bytes

        Non-deterministic signature
        11.5 µs ± 962 ns per loop (mean ± std. dev. of 10 runs, 100,000 loops each)
        Deterministic signature
        7.84 µs ± 156 ns per loop (mean ± std. dev. of 10 runs, 100,000 loops each)

        Timing                              | Best Abs Time | Measure | Comparison
        ----------------------------------- | ------------- | ------- | ---------------------------
        Non-deterministic signature         |       10.6 us |    ⚠    | baseline 
        Deterministic signature             |       7.59 us |    ⚠    | -29% (faster than baseline)

        Payload size: 4200 bytes

        Non-deterministic signature
        28.1 µs ± 3.26 µs per loop (mean ± std. dev. of 10 runs, 10,000 loops each)
        Deterministic signature
        24.2 µs ± 1.43 µs per loop (mean ± std. dev. of 10 runs, 10,000 loops each)

        Timing                              | Best Abs Time | Measure | Comparison
        ----------------------------------- | ------------- | ------- | ---------------------------
        Non-deterministic signature         |       25.7 us |    ⚠    | baseline 
        Deterministic signature             |       22.6 us |    ⚠    | -13% (faster than baseline)
        ```

## BLAKE versions

Different BLAKE versions and modes can perform better or worse depending on the hardware they're running on. For example, BLAKE2b is optimized for 64b platforms whereas BLAKE2s, for 8-32b platforms (read more about them in their [official site](https://blake2.net/)). On the other hand, BLAKE3 is general purpose and designed to be as fast as possible, and it certainly succeeds on being several times faster than BLAKE2 (read more in its [official site](https://github.com/BLAKE3-team/BLAKE3-specs)).

!!! info "BLAKE3"
    In my trials, BLAKE3 turned out to be slower for small payloads than BLAKE2. It could be related to the particular implementation, or it could be designed like that. I will update this information if it changes in the future (it is still very new).

You should test your implementation to see which hasher performs better.

!!! note
    The standard deviation presented on each evaluation should be at least two orders of magnitude lower than the mean for appropriate results.

??? example "Comparing BLAKE versions"
    === "Source"
 
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
                # check if deviation is too big
                ok = (timings[timing].best / timings[timing].stdev) > 60
                print_row(timing, timings[timing].best, ok, baseline)
            print()
        ```

    === "Output"

        ```
        Payload size: 21 bytes
        blake2b
        11.3 µs ± 566 ns per loop (mean ± std. dev. of 10 runs, 100,000 loops each)
        blake2s
        10.1 µs ± 422 ns per loop (mean ± std. dev. of 10 runs, 100,000 loops each)
        blake3
        12.3 µs ± 146 ns per loop (mean ± std. dev. of 10 runs, 100,000 loops each)

        Timing               | Best Abs Time | Measure | Comparison
        -------------------- | ------------- | ------- | ---------------------------
        blake2b              |       10.7 us |    ⚠    | baseline 
        blake2s              |       9.73 us |    ⚠    |  -9% (faster than baseline)
        blake3               |       12.1 us |    √    |  13% (slower than baseline)

        Payload size: 6300 bytes
        blake2b
        34.8 µs ± 1.83 µs per loop (mean ± std. dev. of 10 runs, 10,000 loops each)
        blake2s
        53.5 µs ± 9.36 µs per loop (mean ± std. dev. of 10 runs, 10,000 loops each)
        blake3
        26.3 µs ± 3.09 µs per loop (mean ± std. dev. of 10 runs, 10,000 loops each)

        Timing               | Best Abs Time | Measure | Comparison
        -------------------- | ------------- | ------- | ---------------------------
        blake2b              |       33.3 us |    ⚠    | baseline 
        blake2s              |       45.2 us |    ⚠    |  35% (slower than baseline)
        blake3               |       23.3 us |    ⚠    | -31% (faster than baseline)

        Payload size: 21000 bytes
        blake2b
        95.7 µs ± 3.43 µs per loop (mean ± std. dev. of 10 runs, 10,000 loops each)
        blake2s
        128 µs ± 5.02 µs per loop (mean ± std. dev. of 10 runs, 10,000 loops each)
        blake3
        37.7 µs ± 4.51 µs per loop (mean ± std. dev. of 10 runs, 10,000 loops each)

        Timing               | Best Abs Time | Measure | Comparison
        -------------------- | ------------- | ------- | ---------------------------
        blake2b              |       91.2 us |    ⚠    | baseline 
        blake2s              |        122 us |    ⚠    |  33% (slower than baseline)
        blake3               |       33.7 us |    ⚠    | -64% (faster than baseline)
        ```
