# ROCCA-S: an efficient AES-based encryption scheme

This is an implementation of [ROCCA-S: an efficient AES-based encryption scheme for beyond 5G](https://www.ietf.org/archive/id/draft-nakano-rocca-s-01.html), a very fast authenticated encryption scheme optimized for platforms with AES-NI or ARM crypto extensions.

ROCCA is key committing, has a 256 bit key size, a 128 bit nonce, processes 256 bit message blocks and outputs a 256 bit authentication tag.

Benchmark results on x86_64 (Macbook Pro, 2,4 GHz Core i9, single core):

```text
       aes256-ocb:       4681 MiB/s            
       aes128-ocb:       6040 MiB/s
        aegis-256:       9297 MiB/s
       aegis-128l:      14084 MiB/s
            rocca:      16284 MiB/s (130 Gb/s)
```

Benchmark results on aarch64 (VM on a Freebox Delta home router)

```text
       aes128-ocb:        774 MiB/s
       aes256-ocb:        579 MiB/s
        aegis-256:       1197 MiB/s
       aegis-128l:       1763 MiB/s
            rocca:       2291 MiB/s (18 Gb/s)
```

On Rocket Lake (Xeon E-2386G), AEGIS-128L still outperforms ROCCA:

Zig benchmarks:

```text
       aes128-ocb:      10173 MiB/s
       aes256-ocb:       7792 MiB/s
        aegis-256:      11775 MiB/s
            rocca:      16274 MiB/s
       aegis-128l:      21206 MiB/s (170 Gb/s)
```

OpenSSL 3.0.0 AES-GCM benchmark on the same machine:

```text
       aes128-gcm:       8772 MiB/s
       aes256-gcm:       7483 MiB/s
```

**Warning:** this implementation is for benchmarking and testing purposes only.

ROCCA-S is a newly proposed scheme, and hasn't received any serious attention yet.

AEGIS should always be preferred over ROCCA-S for any actual use.
