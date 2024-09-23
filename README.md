## SwiftSPHINCS

SwiftSPHINCS is a Swift implementation of NIST FIPS 205: *Stateless Hash-Based Digital Signature Standard, August 13, 2024*.

SwiftSPHINCS functionality:

* Support for the 12 parameter sets defined in the standard
* Create public and secret keys
* Sign messages - deterministically or randomized, pure or pre-hashed, with or without context.
* Verify signatures, pure or pre-hashed, with or without context
* Store keys in their PEM encoded ASN1 representation
* Restore keys from their PEM encoded ASN1 representation

SwiftSPHINCS requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

Its documentation is build with the DocC plugin and published on GitHub Pages at this location:

https://leif-ibsen.github.io/SwiftSPHINCS/documentation/swiftsphincs

The documentation is also available in the *SwiftSPHINCS.doccarchive* file.

The KAT test vectors come from the ACVP server release 1.1.0.35.
