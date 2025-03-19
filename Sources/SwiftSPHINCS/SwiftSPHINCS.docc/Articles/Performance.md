# Performance

## 

SwiftSPHINCS's execution time for key generation, signing a 2 kB message and signature verification was measured on a MacBook Pro 2024, Apple M3 chip.

The table below shows the results in seconds or milliseconds for the twelve SPHINCS kinds.

| Kind       | GenerateKeyPair | Sign     | Verify   |
|:-----------|----------------:|---------:|---------:|
| SHA2_128f  | 8.8 mSec        | 0.11 Sec | 5.8 mSec |
| SHA2_128s  | 0.5 Sec         | 2.0 Sec  | 2.1 mSec |
| SHA2_192f  | 12 mSec         | 0.15 Sec | 8.1 mSec |
| SHA2_192s  | 0.7 Sec         | 3.5 Sec  | 2.9 mSec |
| SHA2_256f  | 30 mSec         | 0.30 Sec | 8.2 mSec |
| SHA2_256s  | 0.5 Sec         | 3.0 Sec  | 4.2 mSec |
| SHAKE_128f | 14 mSec         | 0.17 Sec | 9.9 mSec |
| SHAKE_128s | 0.9 Sec         | 3.5 Sec  | 3.3 mSec |
| SHAKE_192f | 21 mSec         | 0.3 Sec  | 14 mSec  |
| SHAKE_192s | 1.4 Sec         | 6.1 Sec  | 4.7 mSec |
| SHAKE_256f | 56 mSec         | 0.6 Sec  | 15 mSec  |
| SHAKE_256s | 0.9 Sec         | 5.4 Sec  | 7.3 mSec |
