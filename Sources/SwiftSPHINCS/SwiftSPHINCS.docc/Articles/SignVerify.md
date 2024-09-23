# Sign and Verify

##

Messages are signed by secret keys and signatures are verified by public keys.
Signatures can be deterministic or randomized and optionally a hash of the message can be signed
instead of the message itself.

### Example

```swift
import SwiftSPHINCS

// Create the SPHINCS keys

let (secretKey, publicKey) = SPHINCS.GenerateKeyPair(kind: .SHA2_128f)

// Deterministic signature
let deterministicSig = secretKey.Sign(message: [1, 2, 3], randomize: false)
print("Deterministic:", publicKey.Verify(message: [1, 2, 3], signature: deterministicSig))

// Randomized signature
let randomizedSig = secretKey.Sign(message: [1, 2, 3], randomize: true)
print("Randomized:", publicKey.Verify(message: [1, 2, 3], signature: randomizedSig))

// Pre-hashed signature
let preHashedSig = secretKey.SignPrehash(message: [1, 2, 3], ph: .SHA256)
print("Pre-hashed:", publicKey.VerifyPrehash(message: [1, 2, 3], signature: preHashedSig, ph: .SHA256))
```

giving:

```
Deterministic: true
Randomized: true
Pre-hashed: true
```
