// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "JailbreakInspector",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "JailbreakInspectorCore",
            targets: ["JailbreakInspectorCore"]
        ),
        .executable(
            name: "JailbreakInspectorApp",
            targets: ["JailbreakInspectorApp"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/securing/IOSSecuritySuite.git", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "JailbreakInspectorCore",
            dependencies: [],
            path: "Sources/JailbreakInspectorCore"
        ),
        .executableTarget(
            name: "JailbreakInspectorApp",
            dependencies: ["JailbreakInspectorCore", "IOSSecuritySuite"],
            path: "Sources/JailbreakInspectorApp"
        ),
        .testTarget(
            name: "JailbreakInspectorCoreTests",
            dependencies: ["JailbreakInspectorCore"],
            path: "Tests/JailbreakInspectorCoreTests"
        )
    ]
)
