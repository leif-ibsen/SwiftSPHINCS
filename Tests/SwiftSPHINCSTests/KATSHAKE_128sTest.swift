//
//  KATSHAKE_128sTest.swift
//  
//
//  Created by Leif Ibsen on 13/05/2024.
//

import XCTest
@testable import SwiftSPHINCS

final class KATSHAKE_128sTest: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katSHAKE_128s", withExtension: "rsp")!
        Util.makeKatTests(&katTests, try Data(contentsOf: url))
    }

    var katTests: [Util.katTest] = []

    func test() throws {
        Util.doKATTest(.SHAKE_128s, katTests)
    }

}
