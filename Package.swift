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
        .package(url: "https://github.com/leif-ibsen/Digest", from: "1.6.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftSPHINCS",
            dependencies: ["Digest"]),
        .testTarget(
            name: "SwiftSPHINCSTests",
            dependencies: ["SwiftSPHINCS"],
            resources: [.copy("Resources/katSHA2_128f.rsp"), .copy("Resources/katSHA2_128s.rsp"),
                        .copy("Resources/katSHA2_192f.rsp"), .copy("Resources/katSHA2_192s.rsp"),
                        .copy("Resources/katSHA2_256f.rsp"), .copy("Resources/katSHA2_256s.rsp"),
                        .copy("Resources/katSHAKE_128f.rsp"), .copy("Resources/katSHAKE_128s.rsp"),
                        .copy("Resources/katSHAKE_192f.rsp"), .copy("Resources/katSHAKE_192s.rsp"),
                        .copy("Resources/katSHAKE_256f.rsp"), .copy("Resources/katSHAKE_256s.rsp")]),
    ]
)
