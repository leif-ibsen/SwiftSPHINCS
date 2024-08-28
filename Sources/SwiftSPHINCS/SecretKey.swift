//
//  File.swift
//  
//
//  Created by Leif Ibsen on 12/12/2023.
//

/// The SPHINCS secret key
public struct SecretKey: Equatable {
    
    // MARK: Initializer
    
    /// Creates a secret key from its key bytes
    ///
    /// - Parameters:
    ///   - kind: The SPHINCS kind
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size or are inconsistent
    public init(kind: SPHINCSKind, keyBytes: Bytes) throws {
        guard keyBytes.count == Parameters.keyByteCount(kind) << 1 else {
            throw SPHINCSException.secretKeySize
        }
        self.kind = kind
        self.keyBytes = keyBytes
        let sphincs = SPHINCS(kind: kind)
        let SKseed = Bytes(self.keyBytes[0 ..< sphincs.param.n])
        let PKseed = Bytes(self.keyBytes[sphincs.param.n * 2 ..< sphincs.param.n * 3])
        var adrs = ADRS()
        adrs.setLayerAddress(sphincs.param.d - 1)
        let PKroot = sphincs.xmssNode(SKseed, 0, sphincs.param.h1, PKseed, adrs)
        guard PKroot == Bytes(keyBytes[sphincs.param.n * 3 ..< sphincs.param.n * 4]) else {
            throw SPHINCSException.invalidSecretKey
        }
        self.publicKey = try PublicKey(kind: kind, keyBytes: PKseed + PKroot)
    }
    
    
    // MARK: Stored Properties
    
    /// The SPHINCS kind
    public let kind: SPHINCSKind
    /// The key bytes
    public let keyBytes: Bytes
    
    /// The corresponding public key
    public let publicKey: PublicKey


    // MARK: Methods
    
    /// Signs a message - pure version
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    public func Sign(message: Bytes, randomize: Bool = true) -> Bytes {
        return SPHINCS(kind: self.kind).slhSign(message, [], self.keyBytes, randomize)
    }
    
    /// Signs a message - pure version with context
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - context: The context string
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    /// - Throws: An exception if the context size is larger than 255
    public func Sign(message: Bytes, context: Bytes, randomize: Bool = true) throws -> Bytes {
        guard context.count < 256 else {
            throw SPHINCSException.contextSize
        }
        return SPHINCS(kind: self.kind).slhSign(message, context, self.keyBytes, randomize)
    }
    
    /// Signs a message - pre-hashed version
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - ph: The pre-hash function
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    public func SignPrehash(message: Bytes, ph: SPHINCSPreHash, randomize: Bool = true) -> Bytes {
        return SPHINCS(kind: self.kind).hashSlhSign(message, [], ph, self.keyBytes, randomize)
    }
    
    /// Signs a message - pre-hashed version with context
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - ph: The pre-hash function
    ///   - context: The context string
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    /// - Throws: An exception if the context size is larger than 255
    public func SignPrehash(message: Bytes, ph: SPHINCSPreHash, context: Bytes, randomize: Bool = true) throws -> Bytes {
        guard context.count < 256 else {
            throw SPHINCSException.contextSize
        }
        return SPHINCS(kind: self.kind).hashSlhSign(message, context, ph, self.keyBytes, randomize)
    }

    /// Equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `true` if key1 = key2, `false` otherwise
    public static func == (key1: SecretKey, key2: SecretKey) -> Bool {
        return key1.keyBytes == key2.keyBytes && key1.kind == key2.kind
    }

    /// Not equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `false` if key1 = key2, `true` otherwise
    public static func != (key1: SecretKey, key2: SecretKey) -> Bool {
        return key1.keyBytes != key2.keyBytes || key1.kind != key2.kind
    }

}

