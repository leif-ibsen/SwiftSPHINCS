//
//  Util.swift
//  
//
//  Created by Leif Ibsen on 07/12/2023.
//

import XCTest
@testable import SwiftSPHINCS

final class Util: XCTestCase {
    
    static func sphincsKind(_ kind: String) -> Kind {
        switch kind {
        case "SLH-DSA-SHA2-128f":
            return Kind.SHA2_128f
        case "SLH-DSA-SHA2-128s":
            return Kind.SHA2_128s
        case "SLH-DSA-SHA2-192f":
            return Kind.SHA2_192f
        case "SLH-DSA-SHA2-192s":
            return Kind.SHA2_192s
        case "SLH-DSA-SHA2-256f":
            return Kind.SHA2_256f
        case "SLH-DSA-SHA2-256s":
            return Kind.SHA2_256s
        case "SLH-DSA-SHAKE-128f":
            return Kind.SHAKE_128f
        case "SLH-DSA-SHAKE-128s":
            return Kind.SHAKE_128s
        case "SLH-DSA-SHAKE-192f":
            return Kind.SHAKE_192f
        case "SLH-DSA-SHAKE-192s":
            return Kind.SHAKE_192s
        case "SLH-DSA-SHAKE-256f":
            return Kind.SHAKE_256f
        case "SLH-DSA-SHAKE-256s":
            return Kind.SHAKE_256s
        default:
            fatalError("Wrong SPHINCS kind: \(kind)")
        }
    }
    
    static func preHash(_ hashAlg: String) -> PreHash? {
        if hashAlg == "none" {
            return nil
        }
        if hashAlg == "SHA2-224" {
            return .SHA2_224
        }
        if hashAlg == "SHA2-256" {
            return .SHA2_256
        }
        if hashAlg == "SHA2-384" {
            return .SHA2_384
        }
        if hashAlg == "SHA2-512" {
            return .SHA2_512
        }
        if hashAlg == "SHA3-224" {
            return .SHA3_224
        }
        if hashAlg == "SHA3-256" {
            return .SHA3_256
        }
        if hashAlg == "SHA3-384" {
            return .SHA3_384
        }
        if hashAlg == "SHA3-512" {
            return .SHA3_512
        }
        if hashAlg == "SHAKE-128" {
            return .SHAKE128
        }
        if hashAlg == "SHAKE-256" {
            return .SHAKE256
        }
        fatalError("Wrong hash algorithm: \(hashAlg)")
    }

}
