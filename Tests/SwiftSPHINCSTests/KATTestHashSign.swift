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

final class KATTestHashSign: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestHashSign", withExtension: "rsp")!
        makeSignHashTests(try Data(contentsOf: url))
    }
    
    struct signHashTest {
        let kind: Kind
        let sk: Bytes
        let message: Bytes
        let context: Bytes
        let hashAlg: PreHash
        let signature: Bytes
    }

    var signHashTests: [signHashTest] = []
    
    func makeSignHashTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 8
        for i in 0 ..< groups {
            let j = i * 8
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(5)
            lines[j + 3].removeFirst(10)
            lines[j + 4].removeFirst(Swift.min(10, lines[j + 4].count))
            lines[j + 5].removeFirst(10)
            lines[j + 6].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 8
            let kind = Util.sphincsKind(lines[j + 1])
            let sk = Base64.hex2bytes(lines[j + 2])!
            let message = Base64.hex2bytes(lines[j + 3])!
            let context = Base64.hex2bytes(lines[j + 4])!
            let hashAlg = Util.preHash(lines[j + 5])
            let signature = Base64.hex2bytes(lines[j + 6])!
            signHashTests.append(signHashTest(kind: kind, sk: sk, message: message, context: context, hashAlg: hashAlg, signature: signature))
        }
    }

    func testHashSign() {
        for t in signHashTests {
            let sphincs = SPHINCS(t.kind)
            let sig = sphincs.hashSlhSign(t.message, t.context, t.hashAlg, t.sk, false)
            XCTAssertEqual(sig, t.signature)
        }
    }

}
