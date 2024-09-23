//
//  File.swift
//  
//
//  Created by Leif Ibsen on 12/12/2023.
//

import Digest
import ASN1

/// The SPHINCS public key
public struct PublicKey: Equatable, CustomStringConvertible {

    let sphincs: SPHINCS
    

    // MARK: Properties

    /// The key bytes
    public internal(set) var keyBytes: Bytes
    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { do { return ASN1Sequence().add(ASN1Sequence().add(self.sphincs.oid)).add(try ASN1BitString(self.keyBytes, 0)) } catch { return ASN1.NULL } } }
    /// The PEM encoding of `self.asn1`
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PUBLIC KEY") } }
    /// A textual representation of the ASN1 encoding of `self`
    public var description: String { get { return self.asn1.description } }

    
    // MARK: Constructors

    init(_ sphincs: SPHINCS, _ keyBytes: Bytes) {
        self.sphincs = sphincs
        self.keyBytes = keyBytes
    }

    /// Creates a public key from its key bytes
    ///
    /// - Parameters:
    ///   - kind: The SPHINCS kind
    ///   - keyBytes: The key bytes
    /// - Throws: An exception if the key bytes has wrong size
    public init(kind: Kind, keyBytes: Bytes) throws {
        guard keyBytes.count == Parameters.paramsFromKind(kind).keySize else {
            throw Exception.publicKeySize(value: keyBytes.count)
        }
        self.init(SPHINCS(kind), keyBytes)
    }

    /// Creates a public key from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The public key PEM encoding
    /// - Throws: An exception if the PEM encoding is wrong
    public init(pem: String) throws {
        guard let der = Base64.pemDecode(pem, "PUBLIC KEY") else {
            throw Exception.pemStructure
        }
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        if seq.getValue().count < 2 {
            throw Exception.asn1Structure
        }
        guard let seq1 = seq.get(0) as? ASN1Sequence else {
            throw Exception.asn1Structure
        }
        guard let bits = seq.get(1) as? ASN1BitString else {
            throw Exception.asn1Structure
        }
        if seq1.getValue().count < 1 {
            throw Exception.asn1Structure
        }
        guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
            throw Exception.asn1Structure
        }
        guard bits.unused == 0 else {
            throw Exception.asn1Structure
        }
        guard let kind = Parameters.kindFromOID(oid) else {
            throw Exception.asn1Structure
        }
        self.init(SPHINCS(kind), bits.bits)
    }


    // MARK: Methods

    /// Verifies a signature - pure version
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    /// - Returns: `true` if the signature is verified, else `false`
    public func Verify(message: Bytes, signature: Bytes) -> Bool {
        return self.sphincs.slhVerify(message, signature, [], self.keyBytes)
    }

    /// Verifies a signature - pure version with context
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    ///   - context: The context string
    /// - Returns: `true` if the signature is verified, else `false`
    public func Verify(message: Bytes, signature: Bytes, context: Bytes) -> Bool {
        return self.sphincs.slhVerify(message, signature, context, self.keyBytes)
    }

    /// Verifies a signature - pre-hashed version
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    ///   - ph: The pre-hash function
    /// - Returns: `true` if the signature is verified, else `false`
    public func Verify(message: Bytes, signature: Bytes, ph: PreHash) -> Bool {
        return self.sphincs.hashSlhVerify(message, signature, [], ph, self.keyBytes)
    }

    /// Verifies a signature - pre-hashed version with context
    /// - Parameters:
    ///   - message: The message to verify against
    ///   - signature: The signature to verify
    ///   - ph: The pre-hash function
    ///   - context: The context string
    /// - Returns: `true` if the signature is verified, else `false`
    public func Verify(message: Bytes, signature: Bytes, ph: PreHash, context: Bytes) -> Bool {
        return self.sphincs.hashSlhVerify(message, signature, context, ph, self.keyBytes)
    }

    /// Equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `true` if key1 = key2, `false` otherwise
    public static func == (key1: PublicKey, key2: PublicKey) -> Bool {
        return key1.keyBytes == key2.keyBytes
    }

    /// Not equal
    ///
    /// - Parameters:
    ///   - key1: First operand
    ///   - key2: Second operand
    /// - Returns: `false` if key1 = key2, `true` otherwise
    public static func != (key1: PublicKey, key2: PublicKey) -> Bool {
        return key1.keyBytes != key2.keyBytes
    }

}
