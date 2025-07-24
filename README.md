# ROCCA-S: an efficient AES-based encryption scheme

This is an implementation of [ROCCA-S: an efficient AES-based encryption scheme for beyond 5G](https://datatracker.ietf.org/doc/draft-nakano-rocca-s/), a fast authenticated encryption scheme optimized for platforms with AES-NI or ARM crypto extensions.

ROCCA-S has a 256 bit key size, a 128 bit nonce, processes 256 bit message blocks and outputs a 256 bit authentication tag.

## Performance

ROCCA-S demonstrates high encryption performance. However, it's important to note that **ROCCA-S is designed with asymmetric performance characteristics** - decryption is expected to be slower than encryption.

### Benchmark Results

Running on modern hardware with AES acceleration (Apple Silicon M4):

| Message Size | Encryption Speed | Decryption Speed | Asymmetry Factor |
| ------------ | ---------------- | ---------------- | ---------------- |
| 64 bytes     | 4.67 Gbps        | 5.45 Gbps        | 0.86x            |
| 256 bytes    | 23.91 Gbps       | 24.01 Gbps       | 1.00x            |
| 1 KB         | 70.34 Gbps       | 60.62 Gbps       | 1.16x            |
| 4 KB         | 140.54 Gbps      | 89.47 Gbps       | 1.57x            |
| 16 KB        | 169.52 Gbps      | 107.31 Gbps      | 1.58x            |
| 64 KB        | **189.78 Gbps**  | 111.82 Gbps      | **1.70x**        |

As shown in the results, the performance asymmetry becomes more pronounced with larger message sizes, with decryption being up to 1.7x slower than encryption for 64 KB messages.

If your application requires consistent performance for both encryption and decryption operations, consider using another symmetric AEAD scheme.
