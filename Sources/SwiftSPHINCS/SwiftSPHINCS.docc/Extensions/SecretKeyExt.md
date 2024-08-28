# ``SwiftSPHINCS/SecretKey``

A secret key signs a message. In the pure version the message itself is signed.
In the pre-hashed version a hash of the message using one of the ``SPHINCSPreHash`` functions is signed.

## Topics

### Properties

- ``kind``
- ``keyBytes``
- ``publicKey``

### Constructor

- ``init(kind:keyBytes:)``

### Sign

- ``Sign(message:randomize:)``
- ``Sign(message:context:randomize:)``
- ``SignPrehash(message:ph:randomize:)``
- ``SignPrehash(message:ph:context:randomize:)``

### Equality

- ``==(_:_:)``
- ``!=(_:_:)``
