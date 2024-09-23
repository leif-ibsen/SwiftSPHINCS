//
//  SignVerifyTest.swift
//  
//
//  Created by Leif Ibsen on 07/12/2023.
//

import XCTest
@testable import SwiftSPHINCS

final class SignVerifyTest: XCTestCase {

    func test() throws {
        let msg = SPHINCS.randomBytes(100)
        for kind in Kind.allCases {
            let (sk, pk) = SPHINCS.GenerateKeyPair(kind: kind)
            XCTAssertTrue(pk.Verify(message: msg, signature: sk.Sign(message: msg, randomize: true)))
            XCTAssertTrue(pk.Verify(message: msg, signature: sk.Sign(message: msg, randomize: false)))
            XCTAssertTrue(pk.Verify(message: [], signature: sk.Sign(message: [], randomize: true)))
            XCTAssertTrue(pk.Verify(message: [], signature: sk.Sign(message: [], randomize: false)))
        }
    }

}
