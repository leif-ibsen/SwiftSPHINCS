# ``SwiftSPHINCS``

Stateless Hash-Based Digital Signature Standard

## Overview

SwiftSPHINCS is a Swift implementation of NIST FIPS 205: *Stateless Hash-Based Digital Signature Standard, August 13, 2024*.

SwiftSPHINCS functionality:

* Support for the 12 parameter sets defined in the standard
* Create public and secret keys
* Sign messages - deterministically or randomized, pure or pre-hashed, with or without context.
* Verify signatures, pure or pre-hashed, with or without context
* Store keys in their PEM encoded ASN1 representation
* Restore keys from their PEM encoded ASN1 representation

### Usage

To use SwiftSPHINCS, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftSPHINCS", from: "3.2.0"),
]
```

SwiftSPHINCS itself depends on the [ASN1](https://leif-ibsen.github.io/ASN1/documentation/asn1), [BigInt](https://leif-ibsen.github.io/BigInt/documentation/bigint) and [Digest](https://leif-ibsen.github.io/Digest/documentation/digest) packages

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.7.0"),
  .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.21.0"),
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.12.0"),
],
```

SwiftSPHINCS does not do big integer arithmetic, but the ASN1 package depends on the BigInt package.

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

- ``SwiftSPHINCS/Kind``
- ``SwiftSPHINCS/PreHash``
- ``SwiftSPHINCS/Exception``

### Additional Information

- <doc:SignVerify>
- <doc:KeyManagement>
- <doc:OIDs>
- <doc:Performance>
- <doc:References>
