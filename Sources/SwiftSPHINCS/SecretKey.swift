//
//  File.swift
//  
//
//  Created by Leif Ibsen on 12/12/2023.
//

import Digest
import ASN1

/// The SPHINCS secret key
public struct SecretKey: Equatable, CustomStringConvertible {
    
    let sphincs: SPHINCS

    
    // MARK: Properties
    
    /// The key bytes
    public internal(set) var keyBytes: Bytes
    /// The corresponding public key
    public internal(set) var publicKey: PublicKey
    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { return ASN1Sequence().add(ASN1.ZERO).add(ASN1Sequence().add(self.sphincs.oid)).add(ASN1OctetString(ASN1OctetString(self.keyBytes).encode())) } }
    /// The PEM encoding of `self.asn1`
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PRIVATE KEY") } }
    /// A textual representation of the ASN1 encoding of `self`
    public var description: String { get { return self.asn1.description } }

    
    // MARK: Constructors
    
    init(_ sphincs: SPHINCS, _ keyBytes: Bytes) throws {
        self.sphincs = sphincs
        self.keyBytes = keyBytes
        let SKseed = Bytes(self.keyBytes[0 ..< self.sphincs.n])
        let PKseed = Bytes(self.keyBytes[self.sphincs.n * 2 ..< self.sphincs.n * 3])
        var adrs = ADRS()
        adrs.setLayerAddress(self.sphincs.d - 1)
        let PKroot = self.sphincs.xmssNode(SKseed, 0, self.sphincs.h1, PKseed, adrs)
        guard PKroot == Bytes(keyBytes[self.sphincs.n * 3 ..< self.sphincs.n * 4]) else {
            throw Exception.invalidSecretKey
        }
        self.publicKey = try PublicKey(kind: sphincs.kind, keyBytes: PKseed + PKroot)
    }

    /// Creates a secret key from its key bytes
    ///
    /// - Parameters:
    ///   - kind: The SPHINCS kind
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size or are inconsistent
    public init(kind: Kind, keyBytes: Bytes) throws {
        guard keyBytes.count == Parameters.paramsFromKind(kind).keySize << 1 else {
            throw Exception.secretKeySize(value: keyBytes.count)
        }
        try self.init(SPHINCS(kind), keyBytes)
    }
    
    /// Creates a secret key from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The secret key PEM encoding
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        guard let der = Base64.pemDecode(pem, "PRIVATE KEY") else {
            throw Exception.pemStructure
        }
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        if seq.getValue().count < 3 {
            throw Exception.asn1Structure
        }
        guard let int = seq.get(0) as? ASN1Integer else {
            throw Exception.asn1Structure
        }
        if int != ASN1.ZERO {
            throw Exception.asn1Structure
        }
        guard let seq1 = seq.get(1) as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        guard let octets = seq.get(2) as? ASN1OctetString else {
            throw Exception.asn1Structure
        }
        if seq1.getValue().count < 1 {
            throw Exception.asn1Structure
        }
        guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
            throw Exception.asn1Structure
        }
        guard let kind = Parameters.kindFromOID(oid) else {
            throw Exception.asn1Structure
        }
        guard let seq2 = try ASN1.build(octets.value) as? ASN1OctetString else {
            throw Exception.asn1Structure
        }
        try self.init(SPHINCS(kind), seq2.value)
    }


    // MARK: Instance Methods
    
    /// Signs a message - pure version
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    public func Sign(message: Bytes, randomize: Bool = true) -> Bytes {
        return self.sphincs.slhSign(message, [], self.keyBytes, randomize)
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
            throw Exception.contextSize(value: context.count)
        }
        return self.sphincs.slhSign(message, context, self.keyBytes, randomize)
    }
    
    /// Signs a message - pre-hashed version
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - ph: The pre-hash function
    ///   - randomize: If `true`, generate a randomized signature, else generate a deterministic signature, default is `true`
    /// - Returns: The signature
    public func Sign(message: Bytes, ph: PreHash, randomize: Bool = true) -> Bytes {
        return self.sphincs.hashSlhSign(message, [], ph, self.keyBytes, randomize)
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
    public func Sign(message: Bytes, ph: PreHash, context: Bytes, randomize: Bool = true) throws -> Bytes {
        guard context.count < 256 else {
            throw Exception.contextSize(value: context.count)
        }
        return self.sphincs.hashSlhSign(message, context, ph, self.keyBytes, randomize)
    }

    /// Equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `true` if key1 = key2, `false` otherwise
    public static func == (key1: SecretKey, key2: SecretKey) -> Bool {
        return key1.keyBytes == key2.keyBytes
    }

    /// Not equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `false` if key1 = key2, `true` otherwise
    public static func != (key1: SecretKey, key2: SecretKey) -> Bool {
        return key1.keyBytes != key2.keyBytes
    }

}

