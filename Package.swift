// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftSPHINCS",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftSPHINCS",
            targets: ["SwiftSPHINCS"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
  		.package(url: "https://github.com/leif-ibsen/ASN1", from: "2.7.0"),
  		.package(url: "https://github.com/leif-ibsen/BigInt", from: "1.21.0"),
  		.package(url: "https://github.com/leif-ibsen/Digest", from: "1.13.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftSPHINCS",
            dependencies: ["BigInt", "ASN1", "Digest"]),
        .testTarget(
            name: "SwiftSPHINCSTests",
            dependencies: ["SwiftSPHINCS"],
            resources: [.copy("Resources/katTestKeyGen.rsp"), .copy("Resources/katTestSign.rsp"), .copy("Resources/katTestVerify.rsp")]),
    ]
)
