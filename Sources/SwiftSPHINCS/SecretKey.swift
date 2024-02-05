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
        guard keyBytes.count == Parameters.n(kind) << 2 else {
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
        guard PKroot == keyBytes.slice(sphincs.param.n * 3, sphincs.param.n).bytes else {
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
    
    /// Signs a message
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    public func Sign(message: Bytes, randomize: Bool = true) -> Bytes {
        return SPHINCS(kind: self.kind).slhSign(message, self.keyBytes, randomize)
    }
    
}

