# ROCCA-S: an efficient AES-based encryption scheme

This is an implementation of [ROCCA-S: an efficient AES-based encryption scheme for beyond 5G](https://www.ietf.org/archive/id/draft-nakano-rocca-s-05.html), a very fast authenticated encryption scheme optimized for platforms with AES-NI or ARM crypto extensions.

ROCCA-S has a 256 bit key size, a 128 bit nonce, processes 256 bit message blocks and outputs a 256 bit authentication tag.

**Warning:** this implementation is for benchmarking and testing purposes only.

**Performance Note:** ROCCA-S is designed with asymmetric performance characteristics - while encryption is fast, decryption is notably slower. If you need consistent performance for both operations, consider using AEGIS instead.
