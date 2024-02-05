# How it Works

## 

There are only three operations available in SwiftSPHINCS:

* Generate keys - ``SPHINCS/GenerateKeyPair()``
* Sign messages - ``SecretKey/Sign(message:randomize:)``
* Verify signatures - ``PublicKey/Verify(message:signature:)``

### Example

```swift
import SwiftSPHINCS

// Create a SPHINCS instance and keys

let sphincs = SPHINCS(kind: .SHA2_128f)
let (sk, pk) = sphincs.GenerateKeyPair()

// Deterministic signature
let deterministicSig = sk.Sign(message: [1, 2, 3], randomize: false)
print("Deterministic:", pk.Verify(message: [1, 2, 3], signature: deterministicSig))

// Randomized signature
let randomizedSig = sk.Sign(message: [1, 2, 3], randomize: true)
print("Randomized:", pk.Verify(message: [1, 2, 3], signature: randomizedSig))
```
giving:
```swift
Deterministic: true

Randomized: true
```
