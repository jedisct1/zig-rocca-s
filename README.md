# ROCCA: an efficient AES-based encryption scheme for beyond 5G

This is an implementation of [ROCCA](https://tosc.iacr.org/index.php/ToSC/article/download/8904/8480/), a very fast encryption scheme on platforms with AES-NI or ARM crypto extensions.

ROCCA is key committing, has a 256 bit key size, a 128 bit nonce, processes 256 bit message blocks and outputs a 128 bit authentication tag.

Benchmark results (2,4 GHz Core i9, single core):

```text
       aes256-ocb:       4681 MiB/s            
       aes128-ocb:       6040 MiB/s
        aegis-256:       9297 MiB/s
       aegis-128l:      14084 MiB/s
            rocca:      16284 MiB/s
```

**Warning:** this implementation is for benchmarking and testing purposes only.

ROCCA is a newly proposed scheme, and hasn't received any serious attention yet.

AEGIS should always be preferred over ROCCA for any actual use.