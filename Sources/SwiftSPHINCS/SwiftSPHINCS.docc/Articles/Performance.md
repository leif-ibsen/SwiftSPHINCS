# Performance

Execution times for certain SwiftSPHINCS operations

## 

SwiftSPHINCS's performance for key generation, signing a 2 kB message and signature verification was measured on an iMac 2021, Apple M1 chip.

The table below shows the figures in seconds or milli seconds for the twelve SPHINCS kinds.

| Kind       | GenerateKeyPair | Sign     | Verify  |
|:-----------|----------------:|---------:|--------:|
| SHA2_128s  | 1.0 Sec         | 3.8 Sec  | 4 mSec  |
| SHAKE_128s | 2.8 Sec         | 10 Sec   | 10 mSec |
| SHA2_128f  | 15 mSec         | 0.18 Sec | 11 mSec |
| SHAKE_128f | 43 mSec         | 0.51 Sec | 30 mSec |
| SHA2_192s  | 1.4 Sec         | 6.7 Sec  | 5 mSec  |
| SHAKE_192s | 4.1 Sec         | 18 Sec   | 15 mSec |
| SHA2_192f  | 22 mSec         | 0.3 Sec  | 16 mSec |
| SHAKE_192f | 63 mSec         | 0.82 Sec | 43 mSec |
| SHA2_256s  | 0.93 Sec        | 5.9 Sec  | 8 mSec  |
| SHAKE_256s | 2.7 Sec         | 16 Sec   | 22 mSec |
| SHA2_256f  | 58 mSec         | 0.60 Sec | 16 mSec |
| SHAKE_256f | 0.16 Sec        | 1.7 Sec  | 44 mSec |

