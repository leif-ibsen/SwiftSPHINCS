//
//  File.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

import ASN1

// Parameters for the twelve kinds
struct Parameters {
    
    let n: Int
    let h: Int
    let d: Int
    let h1: Int
    let a: Int
    let k: Int
    let lgw: Int
    let m: Int
    let mdSize: Int
    let treeSize: Int
    let leafSize: Int
    let treeMask: Int
    let leafMask: Int
    let w: Int
    let len: Int
    let len1: Int
    let len2: Int
    let keySize: Int
    let oid: ASN1ObjectIdentifier
    
    // Figures from [FIPS205] section 11
    
    static let params: [Parameters] = [
        // SHA2_128f
        Parameters(
            n: 16, h: 66, d: 22, h1: 3, a:  6, k: 33, lgw: 4, m: 34,
            mdSize: 25, treeSize: 8, leafSize: 1, treeMask: 0x7fffffffffffffff,
            leafMask: 0x7, w: 16, len: 35, len1: 32, len2: 3, keySize: 32, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.21")!),
        // SHA2_128s
        Parameters(
            n: 16, h: 63, d:  7, h1: 9, a: 12, k: 14, lgw: 4, m: 30,
            mdSize: 21, treeSize: 7, leafSize: 2, treeMask: 0x3fffffffffffff,
            leafMask: 0x1ff, w: 16, len: 35, len1: 32, len2: 3, keySize: 32, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.20")!),
        // SHA2_192f
        Parameters(
            n: 24, h: 66, d: 22, h1: 3, a:  8, k: 33, lgw: 4, m: 42,
            mdSize: 33, treeSize: 8, leafSize: 1, treeMask: 0x7fffffffffffffff,
            leafMask: 0x7, w: 16, len: 51, len1: 48, len2: 3, keySize: 48, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.23")!),
        // SHA2_192s
        Parameters(
            n: 24, h: 63, d:  7, h1: 9, a: 14, k: 17, lgw: 4, m: 39,
            mdSize: 30, treeSize: 7, leafSize: 2, treeMask: 0x3fffffffffffff,
            leafMask: 0x1ff, w: 16, len: 51, len1: 48, len2: 3, keySize: 48, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.22")!),
        // SHA2_256f
        Parameters(
            n: 32, h: 68, d: 17, h1: 4, a:  9, k: 35, lgw: 4, m: 49,
            mdSize: 40, treeSize: 8, leafSize: 1, treeMask: -1,
            leafMask: 0xf, w: 16, len: 67, len1: 64, len2: 3, keySize: 64, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.25")!),
        // SHA2_256s
        Parameters(
            n: 32, h: 64, d:  8, h1: 8, a: 14, k: 22, lgw: 4, m: 47,
            mdSize: 39, treeSize: 7, leafSize: 1, treeMask: 0xffffffffffffff,
            leafMask: 0xff, w: 16, len: 67, len1: 64, len2: 3, keySize: 64, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.24")!),
        // SHAKE_128f
        Parameters(
            n: 16, h: 66, d: 22, h1: 3, a:  6, k: 33, lgw: 4, m: 34,
            mdSize: 25, treeSize: 8, leafSize: 1, treeMask: 0x7fffffffffffffff,
            leafMask: 0x7, w: 16, len: 35, len1: 32, len2: 3, keySize: 32, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.27")!),
        // SHAKE_128s
        Parameters(
            n: 16, h: 63, d:  7, h1: 9, a: 12, k: 14, lgw: 4, m: 30,
            mdSize: 21, treeSize: 7, leafSize: 2, treeMask: 0x3fffffffffffff,
            leafMask: 0x1ff, w: 16, len: 35, len1: 32, len2: 3, keySize: 32, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.26")!),
        // SHAKE_192f
        Parameters(
            n: 24, h: 66, d: 22, h1: 3, a:  8, k: 33, lgw: 4, m: 42,
            mdSize: 33, treeSize: 8, leafSize: 1, treeMask: 0x7fffffffffffffff,
            leafMask: 0x7, w: 16, len: 51, len1: 48, len2: 3, keySize: 48, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.29")!),
        // SHAKE_192s
        Parameters(
            n: 24, h: 63, d:  7, h1: 9, a: 14, k: 17, lgw: 4, m: 39,
            mdSize: 30, treeSize: 7, leafSize: 2, treeMask: 0x3fffffffffffff,
            leafMask: 0x1ff, w: 16, len: 51, len1: 48, len2: 3, keySize: 48, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.28")!),
        // SHAKE_256f
        Parameters(
            n: 32, h: 68, d: 17, h1: 4, a:  9, k: 35, lgw: 4, m: 49,
            mdSize: 40, treeSize: 8, leafSize: 1, treeMask: -1,
            leafMask: 0xf, w: 16, len: 67, len1: 64, len2: 3, keySize: 64, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.31")!),
        // SHAKE_256s
        Parameters(
            n: 32, h: 64, d:  8, h1: 8, a: 14, k: 22, lgw: 4, m: 47,
            mdSize: 39, treeSize: 7, leafSize: 1, treeMask: 0xffffffffffffff,
            leafMask: 0xff, w: 16, len: 67, len1: 64, len2: 3, keySize: 64, oid: ASN1ObjectIdentifier("2.16.840.1.101.3.4.3.30")!)
    ]
    
    static func paramsFromKind(_ kind: Kind) -> Parameters {
        return params[kind.rawValue]
    }
    
    static func kindFromOID(_ oid: ASN1ObjectIdentifier) -> Kind? {
        for kind in Kind.allCases {
            if paramsFromKind(kind).oid == oid {
                return kind
            }
        }
        return nil
    }
    
}
