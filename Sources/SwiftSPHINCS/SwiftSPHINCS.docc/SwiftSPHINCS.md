# ``SwiftSPHINCS``

Stateless Hash-Based Digital Signature Standard

## Overview

SwiftSPHINCS is a Swift implementation of NIST FIPS 205: *Stateless Hash-Based Digital Signature Standard, August 13, 2024*.

SwiftSPHINCS functionality:

* Create public and secret keys
* Sign messages - deterministically or randomized, pure or pre-hashed, with or without context.
* Verify signatures, pure or pre-hashed, with or without context
* Supports all 12 parameter sets defined in the standard

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

// Pre-hashed signature
let preHashedSig = sk.SignPrehash(message: [1, 2, 3], ph: .SHA256)
print("Pre-hashed:", pk.VerifyPrehash(message: [1, 2, 3], signature: preHashedSig, ph: .SHA256))
```
giving:
```swift
Deterministic: true
Randomized: true
Pre-hashed: true
```

### Usage

To use SwiftSPHINCS, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftSPHINCS", from: "2.0.0"),
]
```

SwiftSPHINCS itself depends on the Digest package

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.6.0"),
],
```

> Important:
SwiftSPHINCS requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

### Structures

- ``SwiftSPHINCS/SPHINCS``
- ``SwiftSPHINCS/SecretKey``
- ``SwiftSPHINCS/PublicKey``

### Type Aliases

- ``SwiftSPHINCS/Byte``
- ``SwiftSPHINCS/Bytes``

### Enumerations

- ``SwiftSPHINCS/SPHINCSKind``
- ``SwiftSPHINCS/SPHINCSException``
- ``SwiftSPHINCS/SPHINCSPreHash``

### Additional Information

- <doc:KeyRepresentation>
- <doc:Performance>
- <doc:References>
