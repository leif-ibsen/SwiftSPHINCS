//
//  KATSHAKE_192fTest.swift
//  
//
//  Created by Leif Ibsen on 13/05/2024.
//

import XCTest
@testable import SwiftSPHINCS

final class KATSHAKE_192fTest: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katSHAKE_192f", withExtension: "rsp")!
        Util.makeKatTests(&katTests, try Data(contentsOf: url))
    }

    var katTests: [Util.katTest] = []

    func test() throws {
        Util.doKATTest(.SHAKE_192f, katTests)
    }

}
