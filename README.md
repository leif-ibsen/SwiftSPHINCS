## SwiftSPHINCS

SwiftSPHINCS is a Swift implementation of the proposed PQC (Post Quantum Cryptography)
digital signature mechanism: Stateless Hash-Based Digital Signature Standard.

SwiftSPHINCS functionality:

* Create public and secret keys
* Sign messages - deterministically or randomized
* Verify signatures
* Supports all 12 parameter sets defined in the proposed standard

SwiftSPHINCS requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

Its documentation is build with the DocC tool and published on GitHub Pages at this location:

    https://leif-ibsen.github.io/SwiftSPHINCS/documentation/swiftsphincs

The documentation is also available in the *SwiftSPHINCS.doccarchive* file.