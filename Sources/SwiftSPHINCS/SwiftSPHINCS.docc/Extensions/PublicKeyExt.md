# ``SwiftSPHINCS/PublicKey``

A public key verifies a signature against a message. In the pure version the message itself is verified.
In the pre-hashed version a hash of the message is verified.

## Topics

### Properties

- ``kind``
- ``keyBytes``

### Constructor

- ``init(kind:keyBytes:)``

### Verify

- ``Verify(message:signature:)``
- ``Verify(message:signature:context:)``
- ``VerifyPrehash(message:signature:ph:)``
- ``VerifyPrehash(message:signature:ph:context:)``

### Equality

- ``==(_:_:)``
- ``!=(_:_:)``
