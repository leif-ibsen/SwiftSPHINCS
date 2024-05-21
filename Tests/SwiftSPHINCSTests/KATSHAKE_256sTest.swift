//
//  KATSHAKE_256sTest.swift
//  
//
//  Created by Leif Ibsen on 13/05/2024.
//

import XCTest
@testable import SwiftSPHINCS

final class KATSHAKE_256sTest: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katSHAKE_256s", withExtension: "rsp")!
        Util.makeKatTests(&katTests, try Data(contentsOf: url))
    }

    var katTests: [Util.katTest] = []

    func test() throws {
        Util.doKATTest(.SHAKE_256s, katTests)
    }

}
