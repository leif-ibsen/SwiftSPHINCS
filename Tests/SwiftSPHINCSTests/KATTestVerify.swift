//
//  KATTestVerify.swift
//  
//
//  Created by Leif Ibsen on 26/08/2024.
//

import XCTest
@testable import SwiftSPHINCS
import Digest

// KAT test vectors from NIST ACVP-server version 1.1.0.38.

final class KATTestVerify: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestVerify", withExtension: "rsp")!
        makeVerifyTests(try Data(contentsOf: url))
    }

    struct verifyTest {
        let kind: Kind
        let passed: String
        let pk: Bytes
        let message: Bytes
        let context: Bytes
        let signature: Bytes
    }

    var verifyTests: [verifyTest] = []
    
    func makeVerifyTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 8
        for i in 0 ..< groups {
            let j = i * 8
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(13)
            lines[j + 3].removeFirst(5)
            lines[j + 4].removeFirst(10)
            lines[j + 5].removeFirst(Swift.min(10, lines[j + 5].count))
            lines[j + 6].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 8
            let kind = Util.sphincsKind(lines[j + 1])
            let passed = lines[j + 2]
            let pk = Base64.hex2bytes(lines[j + 3])!
            let message = Base64.hex2bytes(lines[j + 4])!
            let context = Base64.hex2bytes(lines[j + 5])!
            let signature = Base64.hex2bytes(lines[j + 6])!
            verifyTests.append(verifyTest(kind: kind, passed: passed, pk: pk, message: message, context: context, signature: signature))
        }
    }

    func testVerify() {
        for t in verifyTests {
            let sphincs = SPHINCS(t.kind)
            let ok = sphincs.slhVerify(t.message, t.signature, t.context, t.pk)
            XCTAssertEqual(t.passed, ok ? "true" : "false")
        }
    }

}
