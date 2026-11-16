# WolinKit — Official Wolin (月印千江) Swift SDK

[![Swift CI](https://github.com/wolin-id/sdk-swift/actions/workflows/ci.yml/badge.svg)](https://github.com/wolin-id/sdk-swift/actions/workflows/ci.yml)
[![Swift 6.0](https://img.shields.io/badge/Swift-6.0-F05138.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2016%2B%20%7C%20macOS%2013%2B%20%7C%20visionOS%201%2B-blue.svg)](https://developer.apple.com)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-lightgrey.svg)](#license)

**WolinKit** (`wolin-id/sdk-swift`) is the official zero-dependency Swift Package Manager SDK for **[Wolin (月印千江)](https://wolin.id)** and W3C Solid 0.11 servers.

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
- **Safe Signed-Asset Offload Redirects (`302 Found`)**:
  - Intercepts `URLSession` HTTP redirects per-task and follows short-lived HMAC-signed Edge/R2/CDN redirects on `GET` / `HEAD` **without** leaking `Authorization` or `DPoP` headers across origins.
- **`pod_id` Handle Validation**:
  - Built-in `WolinClient.isValidPodID(_:)` and `WolinClient.validatePodID(_:)` (`3..32` chars, lowercase `[a-z0-9-]`, starts/ends with `[a-z0-9]`, no `--`, reserved-handle blocklist).
- **Swift 6.0 Actor Safety & Zero Third-Party Dependencies**:
  - `public actor WolinClient` and `Sendable` value types across **iOS 16+**, **macOS 13+**, and **visionOS 1+**.

---

## Official Production Endpoints

| Service | Endpoint | Constant |
| :--- | :--- | :--- |
| Solid-OIDC Provider & Passport | `https://auth.wolin.id` | `WolinClient.defaultAuthURL` |
| Sovereign Solid Pod Engine | `https://pod.wolin.id` | `WolinClient.defaultPodURL` |

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

// Validate Pod handle format (3..32 chars, lowercase [a-z0-9-], no '--')
try WolinClient.validatePodID("alice")

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

// 3. Dereference WebID Profile, verify Solid-OIDC issuer (https://auth.wolin.id), & discover pim:storage
let profile = try await client.fetchWebIDProfile()
precondition(profile.authorizes(oidcIssuer: WolinClient.defaultAuthURLString))
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

## `pod_id` Format Rules

Wolin Pod handles (`{pod_id}.wolin.id` and `https://pod.wolin.id/pods/{pod_id}/`) enforce strict DNS-label & anti-spoofing rules:

- Length: `3..32` characters
- Characters: lowercase ASCII `[a-z0-9-]`, starting and ending with `[a-z0-9]`
- No consecutive hyphens (`--`)
- Reserved system/infrastructure handles (e.g., `auth`, `pod`, `pods`, `api`, `admin`, `wolin`, `www`) are rejected

```swift
WolinClient.isValidPodID("alice-01")   // true
WolinClient.isValidPodID("ab")         // false (< 3 chars)
WolinClient.isValidPodID("alice--dev") // false (consecutive '--')
WolinClient.isValidPodID("auth")       // false (reserved handle)
```

---

## Package Layout

```text
sdk-swift/
├── Package.swift
├── Sources/
│   └── WolinKit/
│       ├── WolinClient.swift    # Actor-safe Solid-OIDC + DPoP, safe 302 redirects & LDP CRUD client
│       ├── DPoPSigner.swift     # CryptoKit P-256 ES256 DPoP JWT, RFC 7638 jkt & ath
│       ├── WebIdParser.swift    # Pure-Swift W3C Turtle WebID & ldp:contains parser
│       └── PodResource.swift    # PodResource, ETagMatch, LinkRelation & WolinError
└── Tests/
    └── WolinKitTests/
        └── WolinKitTests.swift  # Cryptography, Turtle, pod_id, 302 asset offload & E2E tests
```

---

## License

Copyright (c) 2026 **Entropy Paradox, Inc.** ([https://wolin.id](https://wolin.id)) and Wolin Contributors.

Licensed under either of:

- **Apache License, Version 2.0** ([`LICENSE-APACHE`](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- **MIT License** ([`LICENSE-MIT`](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.
