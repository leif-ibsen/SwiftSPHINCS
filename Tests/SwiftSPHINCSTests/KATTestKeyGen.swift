//
//  KATTestKeyGen.swift
//  
//
//  Created by Leif Ibsen on 26/08/2024.
//

import XCTest
@testable import SwiftSPHINCS
import Digest

// KAT test vectors from NIST ACVP-server version 1.1.0.38.

final class KATTestKeyGen: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katKeyGen", withExtension: "rsp")!
        makeKeyGenTests(try Data(contentsOf: url))
    }

    struct keyGenTest {
        let kind: Kind
        let skSeed: Bytes
        let skPrf: Bytes
        let pkSeed: Bytes
        let sk: Bytes
        let pk: Bytes
    }

    var keyGenTests: [keyGenTest] = []
    
    func makeKeyGenTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 8
        for i in 0 ..< groups {
            let j = i * 8
            lines[j + 1].removeFirst(7)
            lines[j + 2].removeFirst(9)
            lines[j + 3].removeFirst(8)
            lines[j + 4].removeFirst(9)
            lines[j + 5].removeFirst(5)
            lines[j + 6].removeFirst(5)
        }
        for i in 0 ..< groups {
            let j = i * 8
            let kind = Util.sphincsKind(lines[j + 1])
            let skSeed = Base64.hex2bytes(lines[j + 2])!
            let skPrf = Base64.hex2bytes(lines[j + 3])!
            let pkSeed = Base64.hex2bytes(lines[j + 4])!
            let sk = Base64.hex2bytes(lines[j + 5])!
            let pk = Base64.hex2bytes(lines[j + 6])!
            keyGenTests.append(keyGenTest(kind: kind, skSeed: skSeed, skPrf: skPrf, pkSeed: pkSeed, sk: sk, pk: pk))
        }
    }

    func testKeyGen() {
        for t in  keyGenTests {
            let sphincs = SPHINCS(t.kind)
            let (skKey, pkKey) = sphincs.slhKeyGenInternal(t.skSeed, t.skPrf, t.pkSeed)
            XCTAssertEqual(skKey, t.sk)
            XCTAssertEqual(pkKey, t.pk)
        }
    }

}
