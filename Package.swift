// swift-tools-version: 6.0
// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Entropy Paradox, Inc. — Wolin (月印千江) (https://wolin.id)

import PackageDescription

let package = Package(
    name: "WolinKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .visionOS(.v1)
    ],
    products: [
        .library(
            name: "WolinKit",
            targets: ["WolinKit"]
        )
    ],
    targets: [
        .target(
            name: "WolinKit"
        ),
        .testTarget(
            name: "WolinKitTests",
            dependencies: ["WolinKit"]
        )
    ]
)
