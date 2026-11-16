// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Entropy Paradox, Inc. (https://wolin.id)

import XCTest
import Foundation
@preconcurrency import CryptoKit
@testable import WolinKit

final class WolinKitTests: XCTestCase {

    // MARK: - 1. DPoP ES256 Cryptography, JWK Thumbprint & ath Tests

    func testDPoPSignerES256ProofJWKThumbprintAndATH() throws {
        let privateKey = P256.Signing.PrivateKey()
        let signer = DPoPSigner(privateKey: privateKey)

        // Verify RFC 7638 canonical public JWK structure & zero private key leakage
        XCTAssertEqual(signer.publicJWK.kty, "EC")
        XCTAssertEqual(signer.publicJWK.crv, "P-256")
        XCTAssertFalse(signer.publicJWK.canonicalJSON.contains("\"d\""))

        let xBytes = try Base64URL.decode(signer.publicJWK.x)
        let yBytes = try Base64URL.decode(signer.publicJWK.y)
        XCTAssertEqual(xBytes.count, 32)
        XCTAssertEqual(yBytes.count, 32)

        let expectedCanonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(signer.publicJWK.x)\",\"y\":\"\(signer.publicJWK.y)\"}"
        XCTAssertEqual(signer.publicJWK.canonicalJSON, expectedCanonical)
        XCTAssertEqual(signer.jwkThumbprint, Base64URL.sha256(Data(expectedCanonical.utf8)))
        XCTAssertEqual(signer.jwkThumbprint.count, 43)

        // Verify raw & PEM private key round-trips
        let fromRaw = try DPoPSigner(rawRepresentation: privateKey.rawRepresentation)
        let fromPEM = try DPoPSigner(pemRepresentation: privateKey.pemRepresentation)
        XCTAssertEqual(fromRaw.jwkThumbprint, signer.jwkThumbprint)
        XCTAssertEqual(fromPEM.jwkThumbprint, signer.jwkThumbprint)
        XCTAssertEqual(fromRaw.publicJWK, signer.publicJWK)

        // Sign DPoP proof for a URL containing default port, query string, and fragment
        let targetURL = try XCTUnwrap(URL(string: "https://Alice.Wolin.ID:443/pods/alice/private/notes.ttl?view=full#section1"))
        let accessToken = "solid-oidc-access-token-xyz"
        let fixedDate = Date(timeIntervalSince1970: 1_763_500_000)

        let jwt = try signer.signProof(
            httpMethod: "put",
            url: targetURL,
            accessToken: accessToken,
            nonce: "srv-nonce-42",
            jti: "jti-fixed-001",
            issuedAt: fixedDate
        )

        let segments = jwt.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(segments.count, 3)

        let headerData = try Base64URL.decode(String(segments[0]))
        let payloadData = try Base64URL.decode(String(segments[1]))
        let sigData = try Base64URL.decode(String(segments[2]))

        // RFC 7518 Section 3.4: ES256 signature MUST be 64-byte raw R || S
        XCTAssertEqual(sigData.count, 64)

        let decodedHeader = try JSONDecoder().decode(DPoPHeader.self, from: headerData)
        XCTAssertEqual(decodedHeader.typ, "dpop+jwt")
        XCTAssertEqual(decodedHeader.alg, "ES256")
        XCTAssertEqual(decodedHeader.jwk, signer.publicJWK)

        let decodedClaims = try JSONDecoder().decode(DPoPProofClaims.self, from: payloadData)
        XCTAssertEqual(decodedClaims.jti, "jti-fixed-001")
        XCTAssertEqual(decodedClaims.htm, "PUT")
        XCTAssertEqual(decodedClaims.htu, "https://alice.wolin.id/pods/alice/private/notes.ttl")
        XCTAssertEqual(decodedClaims.iat, 1_763_500_000)
        XCTAssertEqual(decodedClaims.ath, Base64URL.sha256(Data(accessToken.utf8)))
        XCTAssertEqual(decodedClaims.nonce, "srv-nonce-42")

        // Cryptographically verify ES256 signature using CryptoKit PublicKey
        let signingInput = Data("\(segments[0]).\(segments[1])".utf8)
        let ecdsaSig = try P256.Signing.ECDSASignature(rawRepresentation: sigData)
        XCTAssertTrue(signer.publicKey.isValidSignature(ecdsaSig, for: signingInput))
    }

    func testDPoPRejectsInvalidSchemesAndUserinfo() throws {
        let signer = DPoPSigner()
        let ftpURL = try XCTUnwrap(URL(string: "ftp://files.example.org/resource.ttl"))
        XCTAssertThrowsError(try signer.signProof(httpMethod: "GET", url: ftpURL)) { error in
            guard case WolinError.invalidDPoPTarget = error else {
                return XCTFail("Expected invalidDPoPTarget, got \(error)")
            }
        }

        var comps = try XCTUnwrap(URLComponents(string: "https://wolin.id/pods/alice/"))
        comps.user = "alice"
        let credentialURL = try XCTUnwrap(comps.url)
        XCTAssertThrowsError(try signer.signProof(httpMethod: "GET", url: credentialURL)) { error in
            guard case WolinError.invalidDPoPTarget = error else {
                return XCTFail("Expected invalidDPoPTarget, got \(error)")
            }
        }
    }

    // MARK: - 2. WebID Turtle Parser & Container Containment Tests

    func testWebIdTurtleParserAndStorageDiscovery() throws {
        let webID = "https://pod.wolin.id/pods/alice/profile/card#me"
        let turtle = """
        # Wolin Solid 0.11 WebID Profile Card
        @prefix foaf: <http://xmlns.com/foaf/0.1/> .
        @prefix solid: <http://www.w3.org/ns/solid/terms#> .
        @prefix pim: <http://www.w3.org/ns/pim/space#> .
        PREFIX ldp: <http://www.w3.org/ns/ldp#>

        <> a foaf:PersonalProfileDocument ;
            foaf:primaryTopic <#me> .

        <#me> a foaf:Person ;
            foaf:name "Alice \\"Sovereign\\" Kim" ;
            solid:oidcIssuer <https://auth.wolin.id> , <https://login.inrupt.com> ;
            pim:storage </pods/alice/> ;
            ldp:inbox <../inbox/> ;
            <http://example.org/ns#bio> \"\"\"Line 1 # not a comment
        Line 2\"\"\" ;
            <http://example.org/ns#meta> [ a <http://example.org/ns#Badge> ; <http://example.org/ns#level> 3 ] ;
        .
        """

        let profile = try WebIdParser.parseTurtle(turtle, webID: webID)
        XCTAssertEqual(profile.webID, webID)
        XCTAssertEqual(profile.name, "Alice \"Sovereign\" Kim")
        XCTAssertEqual(profile.types, ["http://xmlns.com/foaf/0.1/Person"])
        XCTAssertEqual(profile.oidcIssuers, ["https://auth.wolin.id", "https://login.inrupt.com"])
        XCTAssertEqual(profile.storages, ["https://pod.wolin.id/pods/alice/"])
        XCTAssertEqual(profile.inboxes, ["https://pod.wolin.id/pods/alice/inbox/"])
        XCTAssertEqual(profile.primaryStorageURL?.absoluteString, "https://pod.wolin.id/pods/alice/")
        XCTAssertTrue(profile.authorizes(oidcIssuer: "https://auth.wolin.id"))
        XCTAssertFalse(profile.authorizes(oidcIssuer: "https://evil.idp.example"))

        // Verify LDP BasicContainer ldp:contains extraction
        let containerURL = try XCTUnwrap(URL(string: "https://pod.wolin.id/pods/alice/notes/"))
        let containerTurtle = """
        @prefix ldp: <http://www.w3.org/ns/ldp#> .
        <> a ldp:BasicContainer, ldp:Container ;
            ldp:contains <first.ttl>, <second.ttl>, <archive/> .
        """
        let children = try WebIdParser.extractContainedURLs(containerTurtle, containerURL: containerURL)
        XCTAssertEqual(children.map(\.absoluteString), [
            "https://pod.wolin.id/pods/alice/notes/first.ttl",
            "https://pod.wolin.id/pods/alice/notes/second.ttl",
            "https://pod.wolin.id/pods/alice/notes/archive/"
        ])
    }

    // MARK: - 3. Solid LDP CRUD + ETag Preconditions + DPoP Verification End-to-End

    func testSolidLDPCRUDWithETagAndDPoPHeadersEndToEnd() async throws {
        let host = "crud-pod.wolin.test"
        let mockPod = MockSolidPodServer(host: host, expectedToken: "oidc-dpop-token-alice")
        MockSolidRouter.shared.register(host: host) { req, body in
            try mockPod.handle(request: req, body: body)
        }
        defer { MockSolidRouter.shared.unregister(host: host) }

        let session = makeMockSession()
        let webID = "https://\(host)/pods/alice/profile/card#me"
        let client = WolinClient(
            accessToken: "oidc-dpop-token-alice",
            webID: webID,
            session: session
        )

        // 1. Discover pim:storage from WebID Profile Turtle card (unauthenticated public GET)
        let storageURL = try await client.discoverStorage()
        XCTAssertEqual(storageURL.absoluteString, "https://\(host)/pods/alice/")

        // 2. Create RDF resource with If-None-Match: * (.createOnly)
        let noteURL = try XCTUnwrap(URL(string: "https://\(host)/pods/alice/private/note.ttl"))
        let initialTurtle = "<#note> <http://purl.org/dc/terms/title> \"Initial Note\" ."
        let createRes = try await client.putTurtle(
            at: noteURL,
            turtle: initialTurtle,
            etagMatch: .createOnly
        )
        XCTAssertTrue(createRes.created)
        XCTAssertEqual(createRes.statusCode, 201)
        let etagV1 = try XCTUnwrap(createRes.etag)

        // Duplicate createOnly must fail with 412 Precondition Failed
        do {
            _ = try await client.putTurtle(at: noteURL, turtle: initialTurtle, etagMatch: .createOnly)
            XCTFail("Expected 412 Precondition Failed on duplicate If-None-Match: *")
        } catch let WolinError.preconditionFailed(code, _) {
            XCTAssertEqual(code, 412)
        }

        // 3. GET resource and verify ETag, Link metadata, and Turtle payload
        let fetchedV1 = try await client.getResource(at: noteURL, accept: "text/turtle")
        XCTAssertEqual(fetchedV1.statusCode, 200)
        XCTAssertEqual(fetchedV1.etag, etagV1)
        XCTAssertEqual(fetchedV1.kind, .rdfSource)
        XCTAssertEqual(fetchedV1.aclURL?.absoluteString, "https://\(host)/pods/alice/private/note.ttl.acl")
        XCTAssertEqual(fetchedV1.text, initialTurtle)

        // Conditional GET with matching If-None-Match throws .notModified(etag:)
        do {
            _ = try await client.getResource(at: noteURL, etagMatch: .ifNoneMatch(etagV1))
            XCTFail("Expected 304 Not Modified")
        } catch let WolinError.notModified(tag) {
            XCTAssertEqual(tag, etagV1)
        }

        // 4. Stale If-Match update fails with 412; valid If-Match update succeeds with 204 & new ETag
        do {
            _ = try await client.putTurtle(
                at: noteURL,
                turtle: "<#note> <http://purl.org/dc/terms/title> \"Stale Write\" .",
                etagMatch: .ifMatch("\"stale-etag\"")
            )
            XCTFail("Expected 412 Precondition Failed on mismatched ETag")
        } catch let WolinError.preconditionFailed(code, _) {
            XCTAssertEqual(code, 412)
        }

        let updatedTurtle = "<#note> <http://purl.org/dc/terms/title> \"Updated Note v2\" ."
        let updateRes = try await client.putTurtle(
            at: noteURL,
            turtle: updatedTurtle,
            etagMatch: .ifMatch(etagV1)
        )
        XCTAssertFalse(updateRes.created)
        XCTAssertEqual(updateRes.statusCode, 204)
        let etagV2 = try XCTUnwrap(updateRes.etag)
        XCTAssertNotEqual(etagV1, etagV2)

        // 5. SPARQL-Update PATCH with If-Match
        let patchRes = try await client.patchResource(
            at: noteURL,
            sparqlUpdate: "INSERT DATA { <#note> <http://purl.org/dc/terms/subject> \"Solid\" . }",
            etagMatch: .ifMatch(etagV2)
        )
        XCTAssertEqual(patchRes.statusCode, 204)
        let etagV3 = try XCTUnwrap(patchRes.etag)
        XCTAssertNotEqual(etagV2, etagV3)

        // 6. DELETE with If-Match, then verify 404 Not Found
        try await client.deleteResource(at: noteURL, etagMatch: .ifMatch(etagV3))

        do {
            _ = try await client.getResource(at: noteURL)
            XCTFail("Expected 404 Not Found after DELETE")
        } catch let WolinError.notFound(missingURL) {
            XCTAssertEqual(missingURL, noteURL)
        }
    }

    // MARK: - 4. RFC 9449 DPoP-Nonce Retry & Concurrent Actor Safety

    func testDPoPNonceChallengeRetryAndConcurrentActorRequests() async throws {
        let host = "nonce-pod.wolin.test"
        let requiredNonce = "wolin-fresh-nonce-99"
        let attemptCounter = AtomicCounter()

        MockSolidRouter.shared.register(host: host) { req, _ in
            guard let url = req.url else {
                throw WolinError.invalidURL("Missing request URL")
            }
            guard let dpop = req.value(forHTTPHeaderField: "DPoP") else {
                return (
                    HTTPURLResponse(url: url, statusCode: 401, httpVersion: "HTTP/1.1", headerFields: nil)!,
                    Data("Missing DPoP".utf8)
                )
            }
            let claims = try TestDPoPVerifier.extractVerifiedClaims(jwt: dpop)
            _ = attemptCounter.increment()

            if claims.nonce != requiredNonce {
                let headers = ["DPoP-Nonce": requiredNonce]
                let resp = HTTPURLResponse(url: url, statusCode: 401, httpVersion: "HTTP/1.1", headerFields: headers)!
                return (resp, Data("use_dpop_nonce".utf8))
            }

            let headers = [
                "Content-Type": "text/turtle",
                "ETag": "\"nonce-ok\"",
                "DPoP-Nonce": requiredNonce,
                "Link": "<\(SolidVocabulary.ldpRDFSource)>; rel=\"type\""
            ]
            let resp = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!
            return (resp, Data("<#ok> <#status> \"verified\" .".utf8))
        }
        defer { MockSolidRouter.shared.unregister(host: host) }

        let client = WolinClient(
            accessToken: "token-with-nonce",
            webID: "https://\(host)/profile/card#me",
            session: makeMockSession()
        )

        let docURL = try XCTUnwrap(URL(string: "https://\(host)/private/doc.ttl"))
        // First request triggers 401 + DPoP-Nonce challenge and transparently succeeds on retry (2 attempts total)
        let first = try await client.getResource(at: docURL)
        XCTAssertEqual(first.statusCode, 200)
        XCTAssertEqual(attemptCounter.value, 2)

        // Concurrent burst across Swift Tasks reuses cached DPoP-Nonce without extra 401 round-trips
        let tags = try await withThrowingTaskGroup(of: String?.self, returning: [String?].self) { group in
            for idx in 0..<8 {
                let itemURL = try XCTUnwrap(URL(string: "https://\(host)/private/item-\(idx).ttl"))
                group.addTask {
                    let res = try await client.getResource(at: itemURL)
                    return res.etag
                }
            }
            var collected: [String?] = []
            for try await tag in group {
                collected.append(tag)
            }
            return collected
        }
        XCTAssertEqual(tags.count, 8)
        for tag in tags {
            XCTAssertEqual(tag, "\"nonce-ok\"")
        }
        XCTAssertEqual(attemptCounter.value, 10)
    }

    // MARK: - 5. pod_id Validation & Safe 302 Signed-Asset Offload Redirects

    func testPodIDValidationAndProductionEndpoints() throws {
        XCTAssertEqual(WolinClient.defaultAuthURLString, "https://auth.wolin.id")
        XCTAssertEqual(WolinClient.defaultPodURLString, "https://pod.wolin.id")
        XCTAssertEqual(WolinClient.defaultAuthURL.absoluteString, "https://auth.wolin.id")
        XCTAssertEqual(WolinClient.defaultPodURL.absoluteString, "https://pod.wolin.id")

        let validHandles = ["bob", "alice", "alice-01", String(repeating: "a", count: 32), "team-alpha-2026"]
        for valid in validHandles {
            XCTAssertTrue(WolinClient.isValidPodID(valid), valid)
            XCTAssertEqual(try WolinClient.validatePodID(valid), valid)
        }

        let invalidHandles = [
            "", "a", "ab", String(repeating: "a", count: 33), "Alice", "-alice", "alice-",
            "alice--dev", "xn--p1ai", "alice_01", "alice.dev",
            "auth", "pod", "pods", "api", "admin", "wolin", "www"
        ]
        for invalid in invalidHandles {
            XCTAssertFalse(WolinClient.isValidPodID(invalid), invalid)
            XCTAssertThrowsError(try WolinClient.validatePodID(invalid)) { error in
                guard case WolinError.invalidPodID = error else {
                    return XCTFail("Expected invalidPodID for '\(invalid)', got \(error)")
                }
            }
        }
    }

    func testSignedAsset302RedirectStripsAuthorizationAndDPoPHeaders() async throws {
        let podHost = "offload-pod.wolin.test"
        let cdnHost = "offload-cdn.wolin.test"
        let expectedToken = "oidc-dpop-asset-token"
        let assetBytes = Data("wolin-signed-r2-asset-payload".utf8)
        let cdnHitCounter = AtomicCounter()

        MockSolidRouter.shared.register(host: podHost) { req, _ in
            guard let url = req.url else {
                throw WolinError.invalidURL("Missing Pod URL")
            }
            guard req.value(forHTTPHeaderField: "Authorization") == "DPoP \(expectedToken)",
                  let dpop = req.value(forHTTPHeaderField: "DPoP") else {
                let resp = HTTPURLResponse(url: url, statusCode: 401, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (resp, Data("Unauthorized".utf8))
            }
            let claims = try TestDPoPVerifier.extractVerifiedClaims(jwt: dpop)
            XCTAssertEqual(claims.htm, "GET")
            XCTAssertEqual(claims.htu, "https://\(podHost)/pods/alice/media/avatar.png")

            let headers = [
                "Location": "https://\(cdnHost)/assets/alice/media/avatar.png?exp=1763500060&sig=ok",
                "ETag": "\"asset-etag-v1\"",
                "Link": "<\(SolidVocabulary.ldpNonRDFSource)>; rel=\"type\", <https://\(podHost)/pods/alice/media/avatar.png.acl>; rel=\"acl\"",
                "WAC-Allow": "user=\"read write control\",public=\"\"",
                "Cache-Control": "private, no-store"
            ]
            let resp = HTTPURLResponse(url: url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: headers)!
            return (resp, Data())
        }

        MockSolidRouter.shared.register(host: cdnHost) { req, _ in
            guard let url = req.url else {
                throw WolinError.invalidURL("Missing CDN URL")
            }
            _ = cdnHitCounter.increment()
            if req.value(forHTTPHeaderField: "Authorization") != nil || req.value(forHTTPHeaderField: "DPoP") != nil {
                let leak = HTTPURLResponse(url: url, statusCode: 400, httpVersion: "HTTP/1.1", headerFields: nil)!
                return (leak, Data("Credential leak detected on external signed asset CDN".utf8))
            }
            let ok = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "image/png"]
            )!
            return (ok, assetBytes)
        }

        defer {
            MockSolidRouter.shared.unregister(host: podHost)
            MockSolidRouter.shared.unregister(host: cdnHost)
        }

        let client = WolinClient(
            accessToken: expectedToken,
            webID: "https://\(podHost)/pods/alice/profile/card#me",
            session: makeMockSession()
        )

        let assetURL = try XCTUnwrap(URL(string: "https://\(podHost)/pods/alice/media/avatar.png"))
        let resource = try await client.getResource(at: assetURL, accept: "image/png")
        XCTAssertEqual(resource.statusCode, 200)
        XCTAssertEqual(resource.data, assetBytes)
        XCTAssertEqual(resource.contentType, "image/png")
        XCTAssertEqual(resource.etag, "\"asset-etag-v1\"")
        XCTAssertEqual(resource.kind, .nonRdfSource)
        XCTAssertEqual(resource.aclURL?.absoluteString, "https://\(podHost)/pods/alice/media/avatar.png.acl")
        XCTAssertEqual(cdnHitCounter.value, 1)
    }

    // MARK: - Test Helpers

    private func makeMockSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockSolidURLProtocol.self]
        return URLSession(configuration: config)
    }
}

// MARK: - Swift 6 Concurrency-Safe Mock Solid Pod Server & URLProtocol

private enum TestDPoPVerifier {
    static func extractVerifiedClaims(jwt: String) throws -> DPoPProofClaims {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else {
            throw WolinError.cryptographyError("Invalid compact JWT")
        }
        let header = try JSONDecoder().decode(DPoPHeader.self, from: Base64URL.decode(String(parts[0])))
        let claims = try JSONDecoder().decode(DPoPProofClaims.self, from: Base64URL.decode(String(parts[1])))
        let sigBytes = try Base64URL.decode(String(parts[2]))

        let x = try Base64URL.decode(header.jwk.x)
        let y = try Base64URL.decode(header.jwk.y)
        var x963 = Data([0x04])
        x963.append(x)
        x963.append(y)

        let pubKey = try P256.Signing.PublicKey(x963Representation: x963)
        let ecdsaSig = try P256.Signing.ECDSASignature(rawRepresentation: sigBytes)
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        guard pubKey.isValidSignature(ecdsaSig, for: signingInput) else {
            throw WolinError.cryptographyError("DPoP signature verification failed")
        }
        return claims
    }
}

private final class AtomicCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: Int = 0

    @discardableResult
    func increment() -> Int {
        lock.lock()
        defer { lock.unlock() }
        storage += 1
        return storage
    }

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

private final class MockSolidPodServer: @unchecked Sendable {
    private struct StoredResource {
        var data: Data
        var contentType: String
        var etag: String
    }

    private let lock = NSLock()
    private let host: String
    private let expectedToken: String
    private var seenJTIs: Set<String> = []
    private var store: [String: StoredResource] = [:]
    private var version: Int = 0

    init(host: String, expectedToken: String) {
        self.host = host
        self.expectedToken = expectedToken
    }

    func handle(request: URLRequest, body: Data) throws -> (HTTPURLResponse, Data) {
        lock.lock()
        defer { lock.unlock() }

        guard let url = request.url else {
            throw WolinError.invalidURL("Missing request URL")
        }
        let method = (request.httpMethod ?? "GET").uppercased()
        let path = url.path

        // Public WebID Profile Card endpoint
        if path == "/pods/alice/profile/card" && method == "GET" {
            // Ensure public WebID discovery did not leak Authorization header
            if request.value(forHTTPHeaderField: "Authorization") != nil {
                return (
                    HTTPURLResponse(url: url, statusCode: 400, httpVersion: "HTTP/1.1", headerFields: nil)!,
                    Data("Unexpected Authorization header on public WebID card fetch".utf8)
                )
            }
            let card = """
            @prefix foaf: <http://xmlns.com/foaf/0.1/> .
            @prefix solid: <http://www.w3.org/ns/solid/terms#> .
            @prefix pim: <http://www.w3.org/ns/pim/space#> .
            <#me> a foaf:Person ;
                foaf:name "Alice" ;
                solid:oidcIssuer <https://auth.wolin.id> ;
                pim:storage <https://\(host)/pods/alice/> .
            """
            let headers = [
                "Content-Type": "text/turtle",
                "ETag": "\"card-v1\"",
                "Link": "<\(SolidVocabulary.ldpRDFSource)>; rel=\"type\""
            ]
            return (
                HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!,
                Data(card.utf8)
            )
        }

        // Authenticate protected Solid LDP endpoints via Solid-OIDC + RFC 9449 DPoP
        guard let auth = request.value(forHTTPHeaderField: "Authorization"),
              auth == "DPoP \(expectedToken)",
              let dpopJWT = request.value(forHTTPHeaderField: "DPoP") else {
            return (
                HTTPURLResponse(url: url, statusCode: 401, httpVersion: "HTTP/1.1", headerFields: nil)!,
                Data("Unauthorized".utf8)
            )
        }

        let claims = try TestDPoPVerifier.extractVerifiedClaims(jwt: dpopJWT)
        guard claims.htm == method,
              claims.htu == "https://\(host)\(path)",
              claims.ath == DPoPSigner.computeAccessTokenHash(expectedToken),
              seenJTIs.insert(claims.jti).inserted else {
            return (
                HTTPURLResponse(url: url, statusCode: 401, httpVersion: "HTTP/1.1", headerFields: nil)!,
                Data("Invalid or replayed DPoP proof".utf8)
            )
        }

        let ifMatch = request.value(forHTTPHeaderField: "If-Match")
        let ifNoneMatch = request.value(forHTTPHeaderField: "If-None-Match")

        switch method {
        case "GET", "HEAD":
            guard let entry = store[path] else {
                return (
                    HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!,
                    Data("Not Found".utf8)
                )
            }
            if let inm = ifNoneMatch, inm == entry.etag || inm == "*" {
                let headers = ["ETag": entry.etag]
                return (
                    HTTPURLResponse(url: url, statusCode: 304, httpVersion: "HTTP/1.1", headerFields: headers)!,
                    Data()
                )
            }
            let headers = [
                "Content-Type": entry.contentType,
                "ETag": entry.etag,
                "Link": "<\(SolidVocabulary.ldpRDFSource)>; rel=\"type\", <https://\(host)\(path).acl>; rel=\"acl\"",
                "WAC-Allow": "user=\"read write append control\",public=\"\""
            ]
            return (
                HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: headers)!,
                method == "HEAD" ? Data() : entry.data
            )

        case "PUT":
            let existing = store[path]
            if ifNoneMatch == "*" && existing != nil {
                return (
                    HTTPURLResponse(url: url, statusCode: 412, httpVersion: "HTTP/1.1", headerFields: nil)!,
                    Data("Resource already exists".utf8)
                )
            }
            if let im = ifMatch {
                guard let current = existing, current.etag == im else {
                    return (
                        HTTPURLResponse(url: url, statusCode: 412, httpVersion: "HTTP/1.1", headerFields: nil)!,
                        Data("ETag mismatch".utf8)
                    )
                }
            }
            version += 1
            let newETag = "\"etag-v\(version)\""
            let ct = request.value(forHTTPHeaderField: "Content-Type") ?? "text/turtle"
            store[path] = StoredResource(data: body, contentType: ct, etag: newETag)
            let status = existing == nil ? 201 : 204
            var headers = ["ETag": newETag]
            if status == 201 {
                headers["Location"] = url.absoluteString
            }
            return (
                HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!,
                Data()
            )

        case "PATCH":
            guard var current = store[path] else {
                return (
                    HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!,
                    Data("Not Found".utf8)
                )
            }
            if let im = ifMatch, current.etag != im {
                return (
                    HTTPURLResponse(url: url, statusCode: 412, httpVersion: "HTTP/1.1", headerFields: nil)!,
                    Data("ETag mismatch".utf8)
                )
            }
            version += 1
            current.etag = "\"etag-v\(version)\""
            current.data.append(Data("\n".utf8))
            current.data.append(body)
            store[path] = current
            return (
                HTTPURLResponse(url: url, statusCode: 204, httpVersion: "HTTP/1.1", headerFields: ["ETag": current.etag])!,
                Data()
            )

        case "DELETE":
            guard let current = store[path] else {
                return (
                    HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: nil)!,
                    Data("Not Found".utf8)
                )
            }
            if let im = ifMatch, current.etag != im {
                return (
                    HTTPURLResponse(url: url, statusCode: 412, httpVersion: "HTTP/1.1", headerFields: nil)!,
                    Data("ETag mismatch".utf8)
                )
            }
            store.removeValue(forKey: path)
            return (
                HTTPURLResponse(url: url, statusCode: 204, httpVersion: "HTTP/1.1", headerFields: nil)!,
                Data()
            )

        default:
            return (
                HTTPURLResponse(url: url, statusCode: 405, httpVersion: "HTTP/1.1", headerFields: nil)!,
                Data("Method Not Allowed".utf8)
            )
        }
    }
}

private final class MockSolidRouter: @unchecked Sendable {
    typealias Handler = @Sendable (URLRequest, Data) throws -> (HTTPURLResponse, Data)

    static let shared = MockSolidRouter()

    private let lock = NSLock()
    private var handlers: [String: Handler] = [:]

    func register(host: String, handler: @escaping Handler) {
        lock.lock()
        defer { lock.unlock() }
        handlers[host.lowercased()] = handler
    }

    func unregister(host: String) {
        lock.lock()
        defer { lock.unlock() }
        handlers.removeValue(forKey: host.lowercased())
    }

    func handler(for host: String) -> Handler? {
        lock.lock()
        defer { lock.unlock() }
        return handlers[host.lowercased()]
    }
}

private final class MockSolidURLProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool {
        guard let host = request.url?.host?.lowercased() else { return false }
        return MockSolidRouter.shared.handler(for: host) != nil
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let host = request.url?.host?.lowercased(),
              let handler = MockSolidRouter.shared.handler(for: host) else {
            client?.urlProtocol(self, didFailWithError: URLError(.cannotFindHost))
            return
        }

        let bodyData = Self.extractBody(from: request)
        do {
            let (response, data) = try handler(request, bodyData)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            if !data.isEmpty {
                client?.urlProtocol(self, didLoad: data)
            }
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}

    private static func extractBody(from request: URLRequest) -> Data {
        if let body = request.httpBody {
            return body
        }
        guard let stream = request.httpBodyStream else {
            return Data()
        }
        stream.open()
        defer { stream.close() }

        var data = Data()
        let bufferSize = 4096
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        while stream.hasBytesAvailable {
            let readCount = stream.read(buffer, maxLength: bufferSize)
            if readCount > 0 {
                data.append(buffer, count: readCount)
            } else {
                break
            }
        }
        return data
    }
}
