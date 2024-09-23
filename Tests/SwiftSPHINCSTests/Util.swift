//
//  Util.swift
//  
//
//  Created by Leif Ibsen on 07/12/2023.
//

import XCTest
@testable import SwiftSPHINCS

typealias Byte = UInt8
typealias Bytes = [UInt8]

final class Util: XCTestCase {
    
    static func hex2bytes(_ x: String) -> Bytes {
        let b = [Byte](x.utf8)
        var bytes = Bytes(repeating: 0, count: b.count / 2)
        for i in 0 ..< bytes.count {
            let b0 = b[2 * i]
            let b1 = b[2 * i + 1]
            if b0 < 58 {
                bytes[i] = b0 - 48
            } else if b0 < 71 {
                bytes[i] = b0 - 65 + 10
            } else {
                bytes[i] = b0 - 97 + 10
            }
            bytes[i] <<= 4
            if b1 < 58 {
                bytes[i] |= b1 - 48
            } else if b1 < 71 {
                bytes[i] |= b1 - 65 + 10
            } else {
                bytes[i] |= b1 - 97 + 10
            }
        }
        return bytes
    }
    
    static func bytes2hex(_ x: Bytes, _ lowercase: Bool = true) -> String {
        let hexDigits = lowercase ?
        ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"] :
        ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
        var s = ""
        for b in x {
            s.append(hexDigits[Int(b >> 4)])
            s.append(hexDigits[Int(b & 0xf)])
        }
        return s
    }
    
    static func makeSphincs(_ kind: String) -> SPHINCS {
        switch kind {
        case "SHA2_128f":
            return SPHINCS(Kind.SHA2_128f)
        case "SHA2_128s":
            return SPHINCS(Kind.SHA2_128s)
        case "SHA2_192f":
            return SPHINCS(Kind.SHA2_192f)
        case "SHA2_192s":
            return SPHINCS(Kind.SHA2_192s)
        case "SHA2_256f":
            return SPHINCS(Kind.SHA2_256f)
        case "SHA2_256s":
            return SPHINCS(Kind.SHA2_256s)
        case "SHAKE_128f":
            return SPHINCS(Kind.SHAKE_128f)
        case "SHAKE_128s":
            return SPHINCS(Kind.SHAKE_128s)
        case "SHAKE_192f":
            return SPHINCS(Kind.SHAKE_192f)
        case "SHAKE_192s":
            return SPHINCS(Kind.SHAKE_192s)
        case "SHAKE_256f":
            return SPHINCS(Kind.SHAKE_256f)
        case "SHAKE_256s":
            return SPHINCS(Kind.SHAKE_256s)
        default:
            fatalError("Wrong KATTEST kind " + kind)
        }
    }
    
}
