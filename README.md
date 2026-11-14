# WolinKit — Official Wolin Swift SDK

[![Swift CI](https://github.com/wolin-id/sdk-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/wolin-id/sdk-swift/actions/workflows/ci.yml)
[![Swift 6.0](https://img.shields.io/badge/Swift-6.0-F05138.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2016%2B%20%7C%20macOS%2013%2B%20%7C%20visionOS%201%2B-blue.svg)](https://developer.apple.com)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-lightgrey.svg)](#license)

**WolinKit** (`wolin-id/sdk-swift`) is the official zero-dependency Swift Package Manager SDK for the **[Wolin Solid Pod Engine](https://wolin.id)** and W3C Solid 0.11 servers.

Built natively for **Swift 6.0 strict concurrency** using Apple `CryptoKit` and `URLSession`, `WolinKit` provides actor-isolated **Solid-OIDC + RFC 9449 DPoP** authentication, **WebID Turtle** profile parsing, `pim:storage` discovery, and optimistic-concurrency **Solid LDP CRUD** with `ETag` preconditions.

---

## Features

- **RFC 9449 DPoP (`ES256` / NIST P-256) via Apple CryptoKit**:
  - Hardware-accelerated `P256.Signing.PrivateKey` JWS signing (`typ: "dpop+jwt"`, `alg: "ES256"`, 64-byte `R || S` signature).
  - Canonical **RFC 7638** SHA-256 JWK thumbprint (`jkt`) and **RFC 9449** `ath` access-token binding.
  - Per-origin `DPoP-Nonce` caching with automatic `401` challenge retry.
- **WebID Profile & `pim:storage` Discovery**:
  - Pure-Swift W3C RDF 1.1 Turtle parser (`WebIdParser`) extracting `solid:oidcIssuer`, `pim:storage`, `ldp:inbox`, `foaf:name`, and LDP container `ldp:contains` triples.
  - RFC 8288 HTTP `Link` header fallback resolution.
- **Solid LDP CRUD with ETag Preconditions**:
  - `GET`, `HEAD`, `PUT`, `POST`, `PATCH` (`application/sparql-update`), and `DELETE` over `URLSession`.
  - First-class `ETagMatch` (`If-Match`, `If-None-Match`, `.createOnly` / `If-None-Match: *`) optimistic concurrency control.
- **Swift 6.0 Actor Safety & Zero Third-Party Dependencies**:
  - `public actor WolinClient` and `Sendable` value types across **iOS 16+**, **macOS 13+**, and **visionOS 1+**.

---

## Installation (Swift Package Manager)

Add `WolinKit` to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/wolin-id/sdk-swift.git", from: "0.1.0")
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [
            .product(name: "WolinKit", package: "sdk-swift")
        ]
    )
]
```

---

## Quickstart

```swift
import Foundation
import CryptoKit
import WolinKit

// 1. Initialize DPoPSigner (or supply an existing P256.Signing.PrivateKey bound to your OIDC token)
let privateKey = P256.Signing.PrivateKey()
let signer = DPoPSigner(privateKey: privateKey)
print("JWK Thumbprint (cnf.jkt):", signer.jwkThumbprint)

// 2. Create an actor-isolated WolinClient
let client = WolinClient(
    accessToken: "<solid-oidc-dpop-bound-access-token>",
    webID: "https://alice.wolin.id/profile/card#me",
    dpopSigner: signer
)

// 3. Dereference WebID Profile & discover pim:storage
let storageURL = try await client.discoverStorage()

// 4. Create a Turtle RDF resource with If-None-Match: * (.createOnly)
let noteURL = storageURL.appending(path: "private/notes.ttl")
let created = try await client.putTurtle(
    at: noteURL,
    turtle: """
    @prefix dct: <http://purl.org/dc/terms/> .
    <#note1> dct:title "Hello from WolinKit" .
    """,
    etagMatch: .createOnly
)

// 5. Read back with ETag & apply a conditional SPARQL-Update PATCH
let resource = try await client.getResource(at: noteURL)
if let etag = resource.etag {
    try await client.patchResource(
        at: noteURL,
        sparqlUpdate: "INSERT DATA { <#note1> <http://purl.org/dc/terms/subject> \"Solid\" . }",
        etagMatch: .ifMatch(etag)
    )
}

// 6. Delete resource
let latest = try await client.headResource(at: noteURL)
if let etag = latest.etag {
    try await client.deleteResource(at: noteURL, etagMatch: .ifMatch(etag))
}
```

---

## Package Layout

```text
sdk-swift/
├── Package.swift
├── Sources/
│   └── WolinKit/
│       ├── WolinClient.swift    # Actor-safe Solid-OIDC + DPoP & LDP CRUD client
│       ├── DPoPSigner.swift     # CryptoKit P-256 ES256 DPoP JWT, RFC 7638 jkt & ath
│       ├── WebIdParser.swift    # Pure-Swift W3C Turtle WebID & ldp:contains parser
│       └── PodResource.swift    # PodResource, ETagMatch, LinkRelation & WolinError
└── Tests/
    └── WolinKitTests/
        └── WolinKitTests.swift  # Cryptography, Turtle & mock Solid Pod E2E tests
```

---

## License

Copyright (c) 2026 **Entropy Paradox, Inc.** ([https://wolin.id](https://wolin.id)) and Wolin Contributors.

Licensed under either of:

- **Apache License, Version 2.0** ([`LICENSE-APACHE`](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- **MIT License** ([`LICENSE-MIT`](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
