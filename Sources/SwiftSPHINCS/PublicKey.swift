//
//  File.swift
//  
//
//  Created by Leif Ibsen on 12/12/2023.
//

/// The SPHINCS public key
public struct PublicKey: Equatable {

    // MARK: Initializer
    
    /// Creates a public key from its key bytes
    ///
    /// - Parameters:
    ///   - kind: The SPHINCS kind
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size
    public init(kind: SPHINCSKind, keyBytes: Bytes) throws {
        guard keyBytes.count == Parameters.n(kind) << 1 else {
            throw SPHINCSException.publicKeySize
        }
        self.kind = kind
        self.keyBytes = keyBytes
    }


    // MARK: Stored Properties
    
    /// The SPHINCS kind
    public let kind: SPHINCSKind
    /// The key bytes
    public let keyBytes: Bytes

    
    // MARK: Methods

    /// Verifies a signature
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    /// - Returns: `true` if the signature is verified, else `false`
    public func Verify(message: Bytes, signature: Bytes) -> Bool {
        return SPHINCS(kind: self.kind).slhVerify(message, signature, self.keyBytes)
    }

    /// Equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `true` if key1 = key2, `false` otherwise
    public static func == (key1: PublicKey, key2: PublicKey) -> Bool {
        return key1.keyBytes == key2.keyBytes && key1.kind == key2.kind
    }

    /// Not equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `false` if key1 = key2, `true` otherwise
    public static func != (key1: PublicKey, key2: PublicKey) -> Bool {
        return key1.keyBytes != key2.keyBytes || key1.kind != key2.kind
    }

}
