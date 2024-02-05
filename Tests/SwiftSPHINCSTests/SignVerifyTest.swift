//
//  SignVerifyTest.swift
//  
//
//  Created by Leif Ibsen on 07/12/2023.
//

import XCTest
@testable import SwiftSPHINCS

final class SignVerifyTest: XCTestCase {

    func test1() throws {
        let msg = Bytes(repeating: 77, count: 2000)
        for kind in SPHINCSKind.allCases {
            let sphincs = SPHINCS(kind: kind)
            let (sk, pk) = sphincs.GenerateKeyPair()
            XCTAssertTrue(pk.Verify(message: msg, signature: sk.Sign(message: msg)))
            let sk1 = try SecretKey(kind: kind, keyBytes: sk.keyBytes)
            XCTAssertEqual(sk, sk1)
            let pk1 = try PublicKey(kind: kind, keyBytes: pk.keyBytes)
            XCTAssertEqual(pk, pk1)
        }
    }

}
