//
//  ContextTest.swift
//  
//
//  Created by Leif Ibsen on 27/08/2024.
//

import XCTest
@testable import SwiftSPHINCS

final class ContextTest: XCTestCase {

    func test() throws {
        let msg = SPHINCS.randomBytes(100)
        let (sk, pk) = SPHINCS(kind: .SHA2_128f).GenerateKeyPair()
        XCTAssertTrue(pk.Verify(message: msg, signature: try sk.Sign(message: msg, context: []), context: []))
        XCTAssertTrue(pk.Verify(message: msg, signature: try sk.Sign(message: msg, context: [1]), context: [1]))
        XCTAssertFalse(pk.Verify(message: msg, signature: try sk.Sign(message: msg, context: []), context: [1]))
        XCTAssertFalse(pk.Verify(message: msg, signature: try sk.Sign(message: msg, context: [1]), context: []))
    }

}
