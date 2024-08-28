# Performance

Execution times for certain SwiftSPHINCS operations

## 

SwiftSPHINCS's performance for key generation, signing a 2 kB message and signature verification was measured on an iMac 2021, Apple M1 chip.

The table below shows the figures in seconds or milliseconds for the twelve SPHINCS kinds.

| Kind       | GenerateKeyPair | Sign     | Verify  |
|:-----------|----------------:|---------:|--------:|
| SHA2_128s  | 1.0 Sec         | 3.8 Sec  | 4 mSec  |
| SHAKE_128s | 2.7 Sec         | 10 Sec   | 10 mSec |
| SHA2_128f  | 15 mSec         | 0.18 Sec | 11 mSec |
| SHAKE_128f | 42 mSec         | 0.48 Sec | 30 mSec |
| SHA2_192s  | 1.4 Sec         | 6.7 Sec  | 5 mSec  |
| SHAKE_192s | 3.9 Sec         | 18 Sec   | 14 mSec |
| SHA2_192f  | 22 mSec         | 0.3 Sec  | 16 mSec |
| SHAKE_192f | 61 mSec         | 0.8 Sec  | 42 mSec |
| SHA2_256s  | 0.93 Sec        | 5.9 Sec  | 8 mSec  |
| SHAKE_256s | 2.6 Sec         | 15 Sec   | 20 mSec |
| SHA2_256f  | 58 mSec         | 0.60 Sec | 16 mSec |
| SHAKE_256f | 0.16 Sec        | 1.6 Sec  | 42 mSec |

