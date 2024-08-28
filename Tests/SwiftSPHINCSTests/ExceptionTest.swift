//
//  ExceptionTest.swift
//  
//
//  Created by Leif Ibsen on 12/12/2023.
//

import XCTest
@testable import SwiftSPHINCS

final class ExceptionTest: XCTestCase {

    func test() throws {
        for kind in SPHINCSKind.allCases {
            let (sk, pk) = SPHINCS(kind: kind).GenerateKeyPair()
            do {
                var keyBytes = sk.keyBytes
                let n = keyBytes.count / 4
                for i in n * 3 ..< n * 4 {
                    keyBytes[i] = 0
                }
                let _ = try SecretKey(kind: kind, keyBytes: keyBytes)
                XCTFail("Expected invalidSecretKey exception")
            } catch SPHINCSException.invalidSecretKey {
            } catch {
                XCTFail("Expected invalidSecretKey exception")
            }
            do {
                let _ = try SecretKey(kind: kind, keyBytes: sk.keyBytes + [0])
                XCTFail("Expected secretKeySize exception")
            } catch SPHINCSException.secretKeySize {
            } catch {
                XCTFail("Expected secretKeySize exception")
            }
            do {
                let _ = try PublicKey(kind: kind, keyBytes: pk.keyBytes + [0])
                XCTFail("Expected publicKeySize exception")
            } catch SPHINCSException.publicKeySize {
            } catch {
                XCTFail("Expected publicKeySize exception")
            }
            do {
                let _ = try sk.Sign(message: [], context: Bytes(repeating: 0, count: 256))
                XCTFail("Expected contextSize exception")
            } catch SPHINCSException.contextSize {
            } catch {
                XCTFail("Expected contextSize exception")
            }
        }
    }

}
