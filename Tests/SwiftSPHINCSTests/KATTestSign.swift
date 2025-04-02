//
//  KATTestSign.swift
//  
//
//  Created by Leif Ibsen on 26/08/2024.
//

import XCTest
@testable import SwiftSPHINCS
import Digest

// KAT test vectors from NIST ACVP-server version 1.1.0.38.

final class KATTestSign: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestSign", withExtension: "rsp")!
        makeSignTests(try Data(contentsOf: url))
    }
    
    struct signTest {
        let tcId: String
        let kind: Kind
        let interface: String
        let sk: Bytes
        let addRnd: Bytes
        let message: Bytes
        let context: Bytes
        let hashAlg: PreHash?
        let signature: Bytes
    }

    var signTests: [signTest] = []
    
    func makeSignTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 10
        for i in 0 ..< groups {
            let j = i * 10
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(12)
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(9)
            lines[j + 5].removeFirst(10)
            lines[j + 6].removeFirst(Swift.min(10, lines[j + 6].count))
            lines[j + 7].removeFirst(10)
            lines[j + 8].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 10
            let tcId = lines[j]
            let kind = Util.sphincsKind(lines[j + 1])
            let interface = lines[j + 2]
            let sk = Base64.hex2bytes(lines[j + 3])!
            let addRnd = Base64.hex2bytes(lines[j + 4])!
            let message = Base64.hex2bytes(lines[j + 5])!
            let context = Base64.hex2bytes(lines[j + 6])!
            let hashAlg = Util.preHash(lines[j + 7])
            let signature = Base64.hex2bytes(lines[j + 8])!
            signTests.append(signTest(tcId: tcId, kind: kind, interface: interface, sk: sk, addRnd: addRnd, message: message, context: context, hashAlg: hashAlg, signature: signature))
        }
    }

    func testSign() {
        for t in signTests {
            let sphincs = SPHINCS(t.kind)
            var sig: Bytes
            if t.hashAlg == nil {
                if t.interface == "internal" {
                    sig = sphincs.slhSignInternal(t.message, t.sk, t.addRnd)
                } else {
                    sig = sphincs.slhSign(t.message, t.context, t.sk, false)
                }
            } else {
                sig = sphincs.hashSlhSign(t.message, t.context, t.hashAlg!, t.sk, false)
            }
            XCTAssertEqual(sig, t.signature)
        }
    }

}
