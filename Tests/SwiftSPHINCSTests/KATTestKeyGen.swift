//
//  KATTestKeyGen.swift
//  
//
//  Created by Leif Ibsen on 26/08/2024.
//

import XCTest
@testable import SwiftSPHINCS

// KAT test vectors from GitHub ACVP-server release 1.1.0.35.

final class KATTestKeyGen: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestKeyGen", withExtension: "rsp")!
        makeKatTests(try Data(contentsOf: url))
    }

    struct katTest {
        let kind: String
        let skSeed: Bytes
        let skPrf: Bytes
        let pkSeed: Bytes
        let sk: Bytes
        let pk: Bytes
    }

    var katTests: [katTest] = []

    func makeKatTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 8
        for i in 0 ..< groups {
            let j = i * 8
            lines[j + 1].removeFirst(5)
            lines[j + 2].removeFirst(7)
            lines[j + 3].removeFirst(6)
            lines[j + 4].removeFirst(7)
            lines[j + 5].removeFirst(3)
            lines[j + 6].removeFirst(3)
        }
        for i in 0 ..< groups {
            let j = i * 8
            let kind = lines[j + 1]
            let skSeed = Util.hex2bytes(lines[j + 2])
            let skPrf = Util.hex2bytes(lines[j + 3])
            let pkSeed = Util.hex2bytes(lines[j + 4])
            let sk = Util.hex2bytes(lines[j + 5])
            let pk = Util.hex2bytes(lines[j + 6])
            katTests.append(katTest(kind: kind, skSeed: skSeed, skPrf: skPrf, pkSeed: pkSeed, sk: sk, pk: pk))
        }
    }

    func test() throws {
        for t in katTests {
            let sphincs = Util.makeSphincs(t.kind)
            let (skKey, pkKey) = sphincs.slhKeyGenInternal(t.skSeed, t.skPrf, t.pkSeed)
            XCTAssertEqual(skKey, t.sk)
            XCTAssertEqual(pkKey, t.pk)
        }
    }

}
