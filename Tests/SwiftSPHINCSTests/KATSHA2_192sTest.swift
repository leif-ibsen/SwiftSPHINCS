//
//  KATSHA2_192sTest.swift
//  
//
//  Created by Leif Ibsen on 13/05/2024.
//

import XCTest
@testable import SwiftSPHINCS

final class KATSHA2_192sTest: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katSHA2_192s", withExtension: "rsp")!
        Util.makeKatTests(&katTests, try Data(contentsOf: url))
    }

    var katTests: [Util.katTest] = []

    func test() throws {
        Util.doKATTest(.SHA2_192s, katTests)
    }

}
