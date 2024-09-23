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
        for kind in Kind.allCases {
            let (sk, pk) = SPHINCS.GenerateKeyPair(kind: kind)
            do {
                var keyBytes = sk.keyBytes
                let n = keyBytes.count / 4
                for i in n * 3 ..< n * 4 {
                    keyBytes[i] = 0
                }
                let _ = try SecretKey(kind: kind, keyBytes: keyBytes)
                XCTFail("Expected invalidSecretKey exception")
            } catch Exception.invalidSecretKey {
            } catch {
                XCTFail("Expected invalidSecretKey exception")
            }
            do {
                let _ = try SecretKey(kind: kind, keyBytes: sk.keyBytes + [0])
                XCTFail("Expected secretKeySize exception")
            } catch Exception.secretKeySize {
            } catch {
                XCTFail("Expected secretKeySize exception")
            }
            do {
                let _ = try PublicKey(kind: kind, keyBytes: pk.keyBytes + [0])
                XCTFail("Expected publicKeySize exception")
            } catch Exception.publicKeySize {
            } catch {
                XCTFail("Expected publicKeySize exception")
            }
            do {
                let _ = try sk.Sign(message: [], context: Bytes(repeating: 0, count: 256))
                XCTFail("Expected contextSize exception")
            } catch Exception.contextSize {
            } catch {
                XCTFail("Expected contextSize exception")
            }
        }
    }

}
