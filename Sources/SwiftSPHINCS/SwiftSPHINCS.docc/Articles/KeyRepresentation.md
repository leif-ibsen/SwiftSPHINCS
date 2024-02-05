# Key Representation

## 

SwiftSPHINCS keys can be stored as raw bytes and later recreated from the stored bytes.

### Example

```swift
import SwiftSPHINCS

let (secretKey, publicKey) = SPHINCS(kind: .SHA2_128f).GenerateKeyPair()

let secretKeyBytes = secretKey.keyBytes
let publicKeyBytes = publicKey.keyBytes

let newSecretKey = try SecretKey(kind: .SHA2_128f, keyBytes: secretKeyBytes)
let newPublicKey = try PublicKey(kind: .SHA2_128f, keyBytes: publicKeyBytes)

// newSecretKey is now equal to secretKey and newPublicKey is equal to publicKey

assert(newSecretKey == secretKey)
assert(newPublicKey == publicKey)
```
