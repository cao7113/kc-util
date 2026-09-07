// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "kc-util",
    platforms: [
        .macOS(.v15)  
    ],
    products: [
        .library(name: "KeychainKit", targets: ["KeychainKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0")
    ],
    targets: [
        // 1. 定义 Build Plugin Target
        .plugin(
            name: "GenerateVersionPlugin",
            capability: .buildTool()
        ),
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .executableTarget(
            name: "kc-util",
            dependencies: [
                "KeychainKit",
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ],
            plugins: [
                .plugin(name: "GenerateVersionPlugin")
            ]
        ),
        .target(
            name: "KeychainKit"
        ),
        .testTarget(
            name: "KeychainKitTests",
            dependencies: ["KeychainKit"]
        ),
        .testTarget(
            name: "kc-utilTests",
            dependencies: ["kc-util", "KeychainKit"]
        ),
    ],
    swiftLanguageModes: [.v6]

)
