//
//  Untitled.swift
//  SwiftSPHINCS
//
//  Created by Leif Ibsen on 21/09/2024.
//

import XCTest
@testable import SwiftSPHINCS

final class PEMTest: XCTestCase {

    func test() throws {
        for kind in Kind.allCases {
            let (sk, pk) = SPHINCS.GenerateKeyPair(kind: kind)
            let pk1 = try PublicKey(pem: pk.pem)
            let sk1 = try SecretKey(pem: sk.pem)
            XCTAssertEqual(pk, pk1)
            XCTAssertEqual(sk, sk1)
        }
    }

}
