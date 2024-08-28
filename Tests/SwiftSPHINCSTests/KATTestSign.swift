//
//  KATTestSign.swift
//  
//
//  Created by Leif Ibsen on 26/08/2024.
//

import XCTest
@testable import SwiftSPHINCS

final class KATTestSign: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestSign", withExtension: "rsp")!
        makeKatTests(try Data(contentsOf: url))
    }
    
    struct katTest {
        let kind: String
        let sk: Bytes
        let message: Bytes
        let signature: Bytes
    }

    var katTests: [katTest] = []

    func makeKatTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 6
        for i in 0 ..< groups {
            let j = i * 6
            lines[j + 1].removeFirst(5)
            lines[j + 2].removeFirst(3)
            lines[j + 3].removeFirst(8)
            lines[j + 4].removeFirst(10)
        }
        for i in 0 ..< groups {
            let j = i * 6
            let kind = lines[j + 1]
            let sk = Util.hex2bytes(lines[j + 2])
            let message = Util.hex2bytes(lines[j + 3])
            let signature = Util.hex2bytes(lines[j + 4])
            katTests.append(katTest(kind: kind, sk: sk, message: message, signature: signature))
        }
    }

    func test() throws {
        for t in katTests {
            let sphincs = Util.makeSphincs(t.kind)
            let sig = sphincs.slhSignInternal(t.message, t.sk, false)
            XCTAssertEqual(sig, t.signature)
        }
    }

}
