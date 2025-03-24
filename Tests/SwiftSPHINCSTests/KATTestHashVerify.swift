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

final class KATTestHashVerify: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestHashVerify", withExtension: "rsp")!
        makeVerifyHashTests(try Data(contentsOf: url))
    }
    
    struct verifyHashTest {
        let kind: Kind
        let testPassed: String
        let pk: Bytes
        let message: Bytes
        let context: Bytes
        let hashAlg: PreHash
        let signature: Bytes
    }

    var verifyHashTests: [verifyHashTest] = []
    
    func makeVerifyHashTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 9
        for i in 0 ..< groups {
            let j = i * 9
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(13)
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(10)
            lines[j + 5].removeFirst(Swift.min(10, lines[j + 5].count))
            lines[j + 6].removeFirst(10)
            lines[j + 7].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 9
            let kind = Util.sphincsKind(lines[j + 1])
            let testPassed = lines[j + 2]
            let pk = Base64.hex2bytes(lines[j + 3])!
            let message = Base64.hex2bytes(lines[j + 4])!
            let context = Base64.hex2bytes(lines[j + 5])!
            let hashAlg = Util.preHash(lines[j + 6])
            let signature = Base64.hex2bytes(lines[j + 7])!
            verifyHashTests.append(verifyHashTest(kind: kind, testPassed: testPassed, pk: pk, message: message, context: context, hashAlg: hashAlg, signature: signature))
        }
    }

    func testHashVerify() {
        for t in verifyHashTests {
            let sphincs = SPHINCS(t.kind)
            let ok = sphincs.hashSlhVerify(t.message, t.signature, t.context, t.hashAlg, t.pk)
            XCTAssertEqual(t.testPassed, ok ? "true" : "false")
        }
    }
}
