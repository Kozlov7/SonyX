// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SonyX",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "sonyx", targets: ["sonyx"]),
        .library(name: "SonyXCore", targets: ["SonyXCore"]),
    ],
    targets: [
        .target(name: "SonyXCore", resources: [.copy("Resources/geoip-v4.bin"), .copy("Resources/GEOIP-LICENSE.txt")]),
        .executableTarget(name: "sonyx", dependencies: ["SonyXCore"]),
    ]
)
