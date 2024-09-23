# ``SwiftSPHINCS/PublicKey``

A public key verifies a signature against a message. In the pure version the message itself is verified.
In the pre-hashed version a hash of the message is verified.

## Topics

### Properties

- ``keyBytes``
- ``asn1``
- ``pem``
- ``description``

### Constructors

- ``init(kind:keyBytes:)``
- ``init(pem:)``

### Verify

- ``Verify(message:signature:)``
- ``Verify(message:signature:context:)``
- ``Verify(message:signature:ph:)``
- ``Verify(message:signature:ph:context:)``

### Equality

- ``==(_:_:)``
- ``!=(_:_:)``
