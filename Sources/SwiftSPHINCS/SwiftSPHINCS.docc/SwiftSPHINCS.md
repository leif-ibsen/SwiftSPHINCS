# ``SwiftSPHINCS``

## Overview

SwiftSPHINCS is a Swift implementation of the proposed PQC (Post Quantum Cryptography)
digital signature mechanism: Stateless Hash-Based Digital Signature Standard.

SwiftSPHINCS functionality:

* Create public and secret keys
* Sign messages - deterministically or randomized
* Verify signatures
* Supports all 12 parameter sets defined in the proposed standard

> Important:
SwiftSPHINCS requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

- <doc:Usage>
- <doc:HowItWorks>
- <doc:KeyRepresentation>
- <doc:Performance>
- <doc:Dependencies>
- <doc:References>
