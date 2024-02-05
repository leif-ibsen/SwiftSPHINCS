//
//  Util.swift
//  
//
//  Created by Leif Ibsen on 07/12/2023.
//

import XCTest
@testable import SwiftSPHINCS

final class Util: XCTestCase {
/*
    
    # 0/1 SLH-DSA-SHAKE-128f
    Digest: 8ed1eb2ee342f0d8b192bf887cbf913036f4e4d9b20970fdcce1dd94c5cb51aa

    # 0/1 SLH-DSA-SHAKE-128s
    Digest: 4f294d3f01f444fee905846f4d6102451f61be02a173a39c4280471db524dacb

    # 0/1 SLH-DSA-SHAKE-192f
    Digest: fa20dbfa2ae229cdc9a32c56262e9dd795203dd675ba4f7e2fec385c0348d175

    # 0/1 SLH-DSA-SHAKE-192s
    Digest: a96de5862c94fafc003fd3745279758ca83f4ead32ec62b735d4f6b5ac4c1533

    # 0/1 SLH-DSA-SHAKE-256f
    Digest: 09828b9b621b8cbaad99e15dff5e2598c70c7863d0203112c77e56cf70b4981a

    # 0/1 SLH-DSA-SHAKE-256s
    Digest: 88f6b16a981f959e052c301c2c766322500b0f43d18449f16687b7a388b641eb
*/
    static func hex2bytes(_ x: String) -> Bytes {
        let b = [Byte](x.utf8)
        var bytes = Bytes(repeating: 0, count: b.count / 2)
        for i in 0 ..< bytes.count {
            let b0 = b[2 * i]
            let b1 = b[2 * i + 1]
            bytes[i] = ((b0 > 57 ? b0 - 97 + 10 : b0 - 48) << 4) | (b1 > 57 ? b1 - 97 + 10 : b1 - 48)
        }
        return bytes
    }
    
    static func bytes2hex(_ x: Bytes) -> String {
        let hexDigits = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]
        var s = ""
        for b in x {
            s.append(hexDigits[Int(b >> 4)])
            s.append(hexDigits[Int(b & 0xf)])
        }
        return s
    }

}
