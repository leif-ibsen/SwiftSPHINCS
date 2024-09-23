# Key Management

##

SwiftSPHINCS keys can be stored in their PEM encoded ASN1 representation and recreated later.

### Example

```swift
import SwiftSPHINCS

let (secretKey, publicKey) = SPHINCS.GenerateKeyPair(kind: .SHA2_128f)

let secretKeyPem = secretKey.pem
let publicKeyPem = publicKey.pem

print(secretKeyPem)
print()
print(publicKeyPem)
print()

let newSecretKey = try SecretKey(pem: secretKeyPem)
let newPublicKey = try PublicKey(pem: publicKeyPem)

assert(newSecretKey == secretKey)
assert(newPublicKey == publicKey)

print(newSecretKey)
print(newPublicKey)
```

Giving (for example):

```
-----BEGIN PRIVATE KEY-----
MFQCAQAwCwYJYIZIAWUDBAMVBEIEQFnpywuHzU7CxIw8JIA/h3U/eB3Pb+jwQC14SQ80Rp5l8HwP
Gn4nkteccs/9J6Jm6aIpgk61xNi6VLA5yInXOo4=
-----END PRIVATE KEY-----

-----BEGIN PUBLIC KEY-----
MDAwCwYJYIZIAWUDBAMVAyEA8HwPGn4nkteccs/9J6Jm6aIpgk61xNi6VLA5yInXOo4=
-----END PUBLIC KEY-----

Sequence (3):
  Integer: 0
  Sequence (1):
    Object Identifier: 2.16.840.1.101.3.4.3.21
  Octet String (66): 04 40 59 e9 cb 0b 87 cd 4e c2 c4 8c 3c 24 80 3f 87 75 3f 78 1d cf 6f e8 f0 40 2d 78 49 0f 34 46 9e 65 f0 7c 0f 1a 7e 27 92 d7 9c 72 cf fd 27 a2 66 e9 a2 29 82 4e b5 c4 d8 ba 54 b0 39 c8 89 d7 3a 8e

Sequence (2):
  Sequence (1):
    Object Identifier: 2.16.840.1.101.3.4.3.21
  Bit String (256): 11110000 01111100 00001111 00011010 01111110 00100111 10010010 11010111 10011100 01110010 11001111 11111101 00100111 10100010 01100110 11101001 10100010 00101001 10000010 01001110 10110101 11000100 11011000 10111010 01010100 10110000 00111001 11001000 10001001 11010111 00111010 10001110
```
