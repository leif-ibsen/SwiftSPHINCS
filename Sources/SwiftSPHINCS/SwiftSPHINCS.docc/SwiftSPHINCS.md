# ``SwiftSPHINCS``

Stateless Hash-Based Digital Signature Standard

## Overview

SwiftSPHINCS is a Swift implementation of NIST FIPS 205 (Draft): *Stateless Hash-Based Digital Signature Standard, August 2023*.

SwiftSPHINCS functionality:

* Create public and secret keys
* Sign messages - deterministically or randomized
* Verify signatures
* Supports all 12 parameter sets defined in the proposed standard

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

### Usage

To use SwiftSPHINCS, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftSPHINCS", from: "1.1.0"),
]
```

SwiftSPHINCS itself depends on the Digest package

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.3.0"),
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

### Additional Information

- <doc:KeyRepresentation>
- <doc:Performance>
- <doc:References>
