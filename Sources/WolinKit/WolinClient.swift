// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Entropy Paradox, Inc. — Wolin (月印千江) (https://wolin.id)

import Foundation
@preconcurrency import CryptoKit

private final class NoRedirectSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    static let shared = NoRedirectSessionDelegate()

    nonisolated func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }
}

/// Actor-safe W3C Solid 0.11 & Solid-OIDC + RFC 9449 DPoP client for Wolin (月印千江).
public actor WolinClient {
    /// Official Wolin (月印千江) Solid-OIDC Provider & Passport production endpoint.
    public static let defaultAuthURLString = "https://auth.wolin.id"

    /// Official Wolin (月印千江) Sovereign Solid Pod Engine production endpoint.
    public static let defaultPodURLString = "https://pod.wolin.id"

    /// Official Wolin (月印千江) Solid-OIDC Provider & Passport production URL.
    public static let defaultAuthURL = URL(string: defaultAuthURLString)!

    /// Official Wolin (月印千江) Sovereign Solid Pod Engine production URL.
    public static let defaultPodURL = URL(string: defaultPodURLString)!

    /// Minimum allowed character length for a Wolin `pod_id` handle.
    public static let minPodIDLength = 3

    /// Maximum allowed character length for a Wolin `pod_id` handle.
    public static let maxPodIDLength = 32

    /// Canonical reserved system/infrastructure handles blocked by Wolin Cloud & Engine.
    public static let reservedPodIDs: Set<String> = [
        "abuse", "admin", "administrator", "ads", "api", "app", "apps", "assets",
        "auth", "authorize", "autoconfig", "autodiscover", "backup", "beta", "billing", "blog",
        "calendar", "cdn", "chat", "cloud", "consent", "console", "contact", "control",
        "corp", "dashboard", "data", "dev", "dns", "doc", "docs", "download",
        "downloads", "edge", "email", "engine", "enterprise", "entropy", "events", "files",
        "forum", "ftp", "gateway", "git", "graphql", "health", "healthz", "help",
        "home", "host", "hostmaster", "id", "idp", "images", "imap", "img",
        "inbox", "info", "internal", "jwks", "legal", "local", "localhost", "login",
        "logout", "logs", "mail", "mailer", "manage", "mcp", "media", "metrics",
        "mta-sts", "mx", "net", "news", "no-reply", "noreply", "notify", "ns",
        "ns1", "ns2", "ns3", "ns4", "oauth", "official", "oidc", "ops",
        "org", "origin", "passport", "pay", "payment", "payments", "pod", "pods",
        "pop", "pop3", "portal", "postmaster", "press", "pricing", "private", "prod",
        "production", "profile", "proxy", "pub", "public", "register", "registry", "relay",
        "root", "rpc", "rss", "sandbox", "search", "secure", "security", "server",
        "service", "services", "session", "settings", "sftp", "signin", "signout", "signup",
        "smtp", "solid", "sparql", "ssh", "sso", "stage", "staging", "static",
        "stats", "status", "storage", "store", "support", "sync", "sys", "system",
        "team", "telemetry", "terms", "test", "testing", "token", "trust", "updates",
        "upload", "uploads", "userinfo", "vault", "verify", "vpn", "wac", "web",
        "webhook", "webhooks", "webid", "webmail", "webmaster", "well-known", "wolin", "ws",
        "wss", "www"
    ]

    private static let redirectStatusCodes: Set<Int> = [301, 302, 303, 307, 308]
    private static let maxSafeRedirects = 5

    /// Validates a Wolin `pod_id` handle (`3..32` chars, lowercase ASCII `[a-z0-9-]`,
    /// starts and ends with `[a-z0-9]`, no consecutive `'--'`, and not reserved).
    @discardableResult
    public static func validatePodID(_ podID: String) throws -> String {
        let count = podID.utf8.count
        guard count >= minPodIDLength && count <= maxPodIDLength, podID.count == count else {
            throw WolinError.invalidPodID(
                "pod_id must be between \(minPodIDLength) and \(maxPodIDLength) lowercase ASCII characters"
            )
        }
        guard !podID.hasPrefix("-"), !podID.hasSuffix("-") else {
            throw WolinError.invalidPodID(
                "pod_id must contain only lowercase ASCII [a-z0-9-] and start and end with [a-z0-9]"
            )
        }
        for byte in podID.utf8 {
            let isLower = byte >= 0x61 && byte <= 0x7A
            let isDigit = byte >= 0x30 && byte <= 0x39
            let isHyphen = byte == 0x2D
            if !isLower && !isDigit && !isHyphen {
                throw WolinError.invalidPodID(
                    "pod_id must contain only lowercase ASCII [a-z0-9-] and start and end with [a-z0-9]"
                )
            }
        }
        if podID.contains("--") {
            throw WolinError.invalidPodID("pod_id must not contain consecutive hyphens ('--')")
        }
        if reservedPodIDs.contains(podID) {
            throw WolinError.invalidPodID("pod_id '\(podID)' is reserved for system infrastructure")
        }
        return podID
    }

    /// Returns `true` if `podID` satisfies all Wolin `pod_id` syntax and reservation rules.
    public static func isValidPodID(_ podID: String) -> Bool {
        (try? validatePodID(podID)) != nil
    }

    /// Immutable ES256 DPoP signer bound to this client session.
    public let dpopSigner: DPoPSigner

    private var accessToken: String?
    private var webID: String?
    private var cachedStorageURL: URL?
    private var dpopNonces: [String: String]
    private let session: URLSession

    /// Initializes a `WolinClient` with optional Solid-OIDC credentials, a CryptoKit P-256 `DPoPSigner`, and a `URLSession`.
    public init(
        accessToken: String? = nil,
        webID: String? = nil,
        dpopSigner: DPoPSigner = DPoPSigner(),
        session: URLSession = .shared
    ) {
        self.accessToken = accessToken
        self.webID = webID
        self.dpopSigner = dpopSigner
        self.cachedStorageURL = nil
        self.dpopNonces = [:]
        self.session = session
    }

    /// Designated initializer accepting a CryptoKit `P256.Signing.PrivateKey` directly.
    public init(
        privateKey: P256.Signing.PrivateKey,
        accessToken: String? = nil,
        webID: String? = nil,
        session: URLSession = .shared
    ) {
        self.accessToken = accessToken
        self.webID = webID
        self.dpopSigner = DPoPSigner(privateKey: privateKey)
        self.cachedStorageURL = nil
        self.dpopNonces = [:]
        self.session = session
    }

    // MARK: - Session Credentials

    /// Updates the Solid-OIDC access token and active WebID URI in actor-isolated storage.
    public func setCredentials(accessToken: String?, webID: String?) {
        if self.webID != webID {
            self.cachedStorageURL = nil
        }
        self.accessToken = accessToken
        self.webID = webID
    }

    /// Clears active Solid-OIDC credentials and cached Pod storage metadata.
    public func clearCredentials() {
        self.accessToken = nil
        self.webID = nil
        self.cachedStorageURL = nil
    }

    /// Returns the currently configured WebID URI, if any.
    public func currentWebID() -> String? {
        webID
    }

    /// Returns the currently configured Solid-OIDC access token, if any.
    public func currentAccessToken() -> String? {
        accessToken
    }

    // MARK: - WebID Profile & pim:storage Discovery

    /// Dereferences a Solid WebID Profile document (`text/turtle`) and parses `solid:oidcIssuer`, `pim:storage`, and `ldp:inbox`.
    /// - Parameters:
    ///   - targetWebID: Explicit WebID URI to dereference, or `nil` to use the client's active `webID`.
    ///   - authenticated: Whether to attach Solid-OIDC DPoP credentials (defaults to `false` so access tokens are not leaked to external WebID hosts).
    public func fetchWebIDProfile(
        for targetWebID: String? = nil,
        authenticated: Bool = false
    ) async throws -> WebIdProfile {
        guard let rawWebID = (targetWebID ?? webID)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !rawWebID.isEmpty else {
            throw WolinError.invalidWebIDProfile("No WebID URI provided or configured on WolinClient")
        }

        let docIRI = String(rawWebID.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? Substring(rawWebID))
        guard let docURL = URL(string: docIRI),
              let components = URLComponents(url: docURL, resolvingAgainstBaseURL: true),
              let scheme = components.scheme?.lowercased(),
              (scheme == "https" || scheme == "http"),
              components.user == nil,
              components.password == nil,
              components.query == nil,
              components.host != nil else {
            throw WolinError.invalidURL(rawWebID)
        }

        let (data, response, _) = try await performSafeReadRequest(
            method: "GET",
            url: docURL,
            headers: ["Accept": "text/turtle, application/x-turtle;q=0.9"],
            etagMatch: .any,
            attachAuth: authenticated
        )

        try validateSuccessStatus(response: response, data: data, requestURL: docURL)

        guard let turtleText = String(data: data, encoding: .utf8) else {
            throw WolinError.invalidWebIDProfile("WebID Profile response is not valid UTF-8")
        }

        var profile = try WebIdParser.parseTurtle(
            turtleText,
            webID: rawWebID,
            baseIRI: docURL.absoluteString
        )

        // Fallback: check RFC 8288 HTTP Link headers for pim:storage / ldp:inbox if omitted from body triples.
        if let linkHeader = response.value(forHTTPHeaderField: "Link") {
            let relations = LinkRelation.parseAll(linkHeader)
            var storages = profile.storages
            var inboxes = profile.inboxes
            for relation in relations {
                let resolved = (try? WebIdParser.resolveIRI(relation.target, base: docURL.absoluteString)) ?? relation.target
                if relation.rel == SolidVocabulary.pimStorage && !storages.contains(resolved) {
                    storages.append(resolved)
                } else if relation.rel == SolidVocabulary.ldpInbox && !inboxes.contains(resolved) {
                    inboxes.append(resolved)
                }
            }
            if storages != profile.storages || inboxes != profile.inboxes {
                profile = WebIdProfile(
                    webID: profile.webID,
                    types: profile.types,
                    name: profile.name,
                    oidcIssuers: profile.oidcIssuers,
                    storages: storages,
                    inboxes: inboxes
                )
            }
        }

        if rawWebID == self.webID, let primary = profile.primaryStorageURL {
            self.cachedStorageURL = primary
        }

        return profile
    }

    /// Discovers the Solid Pod storage root URL (`pim:storage`) for the given or active WebID.
    public func discoverStorage(
        for targetWebID: String? = nil,
        forceRefresh: Bool = false
    ) async throws -> URL {
        let effectiveWebID = (targetWebID ?? webID)?.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let resolvedWebID = effectiveWebID, !resolvedWebID.isEmpty else {
            throw WolinError.invalidWebIDProfile("No WebID URI provided for storage discovery")
        }

        if !forceRefresh, resolvedWebID == self.webID, let cached = cachedStorageURL {
            return cached
        }

        let profile = try await fetchWebIDProfile(for: resolvedWebID, authenticated: false)
        guard let storageURL = profile.primaryStorageURL else {
            throw WolinError.storageNotFound(webID: resolvedWebID)
        }

        if resolvedWebID == self.webID {
            cachedStorageURL = storageURL
        }
        return storageURL
    }

    // MARK: - Solid LDP CRUD Operations

    /// Retrieves a Solid Pod LDP resource via `GET`, including `ETag`, `Link` metadata, and payload bytes.
    /// Safely follows `302 Found` signed asset offload redirects without leaking `Authorization` or `DPoP` headers across origins.
    public func getResource(
        at url: URL,
        accept: String? = nil,
        etagMatch: ETagMatch = .any
    ) async throws -> PodResource {
        var headers: [String: String] = [:]
        if let accept {
            headers["Accept"] = accept
        }
        let (data, response, fallbackResponse) = try await performSafeReadRequest(
            method: "GET",
            url: url,
            headers: headers,
            etagMatch: etagMatch,
            attachAuth: true
        )
        if response.statusCode == 304 {
            let etag = response.value(forHTTPHeaderField: "ETag")
                ?? fallbackResponse?.value(forHTTPHeaderField: "ETag")
            throw WolinError.notModified(etag: etag)
        }
        try validateSuccessStatus(response: response, data: data, requestURL: url)
        return buildPodResource(url: url, response: response, data: data, fallbackResponse: fallbackResponse)
    }

    /// Retrieves Solid Pod LDP resource metadata and `ETag` via `HEAD` without downloading the body.
    public func headResource(
        at url: URL,
        etagMatch: ETagMatch = .any
    ) async throws -> PodResource {
        let (data, response, fallbackResponse) = try await performSafeReadRequest(
            method: "HEAD",
            url: url,
            headers: [:],
            etagMatch: etagMatch,
            attachAuth: true
        )
        if response.statusCode == 304 {
            let etag = response.value(forHTTPHeaderField: "ETag")
                ?? fallbackResponse?.value(forHTTPHeaderField: "ETag")
            throw WolinError.notModified(etag: etag)
        }
        try validateSuccessStatus(response: response, data: data, requestURL: url)
        return buildPodResource(url: url, response: response, data: Data(), fallbackResponse: fallbackResponse)
    }

    /// Creates or replaces a Solid Pod LDP resource via `PUT` with optional `If-Match` / `If-None-Match` ETag preconditions.
    @discardableResult
    public func putResource(
        at url: URL,
        data: Data,
        contentType: String = "text/turtle",
        linkType: String? = nil,
        etagMatch: ETagMatch = .any
    ) async throws -> PodWriteResult {
        var headers: [String: String] = ["Content-Type": contentType]
        if let linkType {
            headers["Link"] = "<\(linkType)>; rel=\"type\""
        }

        let (respData, response) = try await performRequest(
            method: "PUT",
            url: url,
            headers: headers,
            body: data,
            etagMatch: etagMatch,
            attachAuth: true
        )
        try validateSuccessStatus(response: response, data: respData, requestURL: url)
        return buildWriteResult(defaultURL: url, response: response)
    }

    /// Convenience helper to write a UTF-8 Turtle RDF document via `PUT`.
    @discardableResult
    public func putTurtle(
        at url: URL,
        turtle: String,
        etagMatch: ETagMatch = .any
    ) async throws -> PodWriteResult {
        try await putResource(
            at: url,
            data: Data(turtle.utf8),
            contentType: "text/turtle",
            linkType: SolidVocabulary.ldpRDFSource,
            etagMatch: etagMatch
        )
    }

    /// Creates a Solid LDP BasicContainer (`PUT` with trailing `/` and `ldp:BasicContainer` Link header).
    @discardableResult
    public func createContainer(
        at url: URL,
        etagMatch: ETagMatch = .createOnly
    ) async throws -> PodWriteResult {
        let containerURL: URL
        if url.absoluteString.hasSuffix("/") {
            containerURL = url
        } else if let appended = URL(string: url.absoluteString + "/") {
            containerURL = appended
        } else {
            throw WolinError.invalidURL(url.absoluteString)
        }

        return try await putResource(
            at: containerURL,
            data: Data(),
            contentType: "text/turtle",
            linkType: SolidVocabulary.ldpBasicContainer,
            etagMatch: etagMatch
        )
    }

    /// Creates a child LDP resource inside an existing container via `POST` with an optional `Slug` hint.
    @discardableResult
    public func postResource(
        to containerURL: URL,
        data: Data,
        contentType: String = "text/turtle",
        slug: String? = nil,
        linkType: String? = nil
    ) async throws -> PodWriteResult {
        var headers: [String: String] = ["Content-Type": contentType]
        if let slug, !slug.isEmpty {
            headers["Slug"] = slug
        }
        if let linkType {
            headers["Link"] = "<\(linkType)>; rel=\"type\""
        }

        let (respData, response) = try await performRequest(
            method: "POST",
            url: containerURL,
            headers: headers,
            body: data,
            etagMatch: .any,
            attachAuth: true
        )
        try validateSuccessStatus(response: response, data: respData, requestURL: containerURL)
        return buildWriteResult(defaultURL: containerURL, response: response)
    }

    /// Applies an incremental SPARQL 1.1 Update (`Content-Type: application/sparql-update`) via `PATCH`.
    @discardableResult
    public func patchResource(
        at url: URL,
        sparqlUpdate: String,
        etagMatch: ETagMatch = .any
    ) async throws -> PodWriteResult {
        let (respData, response) = try await performRequest(
            method: "PATCH",
            url: url,
            headers: ["Content-Type": "application/sparql-update"],
            body: Data(sparqlUpdate.utf8),
            etagMatch: etagMatch,
            attachAuth: true
        )
        try validateSuccessStatus(response: response, data: respData, requestURL: url)
        return buildWriteResult(defaultURL: url, response: response)
    }

    /// Deletes a Solid Pod LDP resource via `DELETE` with optional `If-Match` ETag precondition.
    public func deleteResource(
        at url: URL,
        etagMatch: ETagMatch = .any
    ) async throws {
        let (respData, response) = try await performRequest(
            method: "DELETE",
            url: url,
            headers: [:],
            body: nil,
            etagMatch: etagMatch,
            attachAuth: true
        )
        try validateSuccessStatus(response: response, data: respData, requestURL: url)
    }

    /// Lists child URLs (`ldp:contains`) of a Solid LDP Container.
    public func listContainer(at containerURL: URL) async throws -> [URL] {
        let resource = try await getResource(at: containerURL, accept: "text/turtle")
        guard let turtle = resource.text else {
            return []
        }
        return try WebIdParser.extractContainedURLs(turtle, containerURL: containerURL)
    }

    // MARK: - Internal Transport, Safe Redirects & DPoP Proof Attachment

    private func performSafeReadRequest(
        method: String,
        url: URL,
        headers: [String: String],
        etagMatch: ETagMatch,
        attachAuth: Bool
    ) async throws -> (Data, HTTPURLResponse, HTTPURLResponse?) {
        var (data, response) = try await performRequest(
            method: method,
            url: url,
            headers: headers,
            body: nil,
            etagMatch: etagMatch,
            attachAuth: attachAuth
        )

        guard Self.redirectStatusCodes.contains(response.statusCode) else {
            return (data, response, nil)
        }

        let podRedirectResponse = response
        let initialOrigin = originKey(for: url)
        var currentURL = url

        for _ in 0..<Self.maxSafeRedirects {
            guard let rawLocation = response.value(forHTTPHeaderField: "Location")?
                .trimmingCharacters(in: .whitespacesAndNewlines),
                  !rawLocation.isEmpty else {
                return (data, response, podRedirectResponse)
            }

            let nextURL = try resolveSafeRedirectURL(rawLocation, baseURL: currentURL)
            let sameOrigin = originKey(for: nextURL) == initialOrigin

            var redirectHeaders: [String: String] = [:]
            if let accept = headers["Accept"] {
                redirectHeaders["Accept"] = accept
            }

            (data, response) = try await performRequest(
                method: method,
                url: nextURL,
                headers: redirectHeaders,
                body: nil,
                etagMatch: .any,
                attachAuth: attachAuth && sameOrigin
            )
            currentURL = nextURL

            if !Self.redirectStatusCodes.contains(response.statusCode) {
                return (data, response, podRedirectResponse)
            }
        }

        throw WolinError.transportError(
            "Exceeded maximum redirect hops (\(Self.maxSafeRedirects)) while reading '\(url.absoluteString)'"
        )
    }

    private func resolveSafeRedirectURL(_ rawLocation: String, baseURL: URL) throws -> URL {
        let resolvedString = try WebIdParser.resolveIRI(rawLocation, base: baseURL.absoluteString)
        guard let targetURL = URL(string: resolvedString),
              let comps = URLComponents(url: targetURL, resolvingAgainstBaseURL: true),
              let scheme = comps.scheme?.lowercased(),
              (scheme == "http" || scheme == "https"),
              comps.user == nil,
              comps.password == nil,
              comps.host != nil else {
            throw WolinError.invalidURL(rawLocation)
        }
        return targetURL
    }

    private func performRequest(
        method: String,
        url: URL,
        headers: [String: String],
        body: Data?,
        etagMatch: ETagMatch,
        attachAuth: Bool
    ) async throws -> (Data, HTTPURLResponse) {
        let origin = originKey(for: url)
        let activeToken = attachAuth ? accessToken : nil
        let initialNonce = dpopNonces[origin]

        let (firstData, firstResponse) = try await sendOnce(
            method: method,
            url: url,
            headers: headers,
            body: body,
            etagMatch: etagMatch,
            token: activeToken,
            nonce: initialNonce
        )

        if let updatedNonce = firstResponse.value(forHTTPHeaderField: "DPoP-Nonce")?
            .trimmingCharacters(in: .whitespacesAndNewlines),
           !updatedNonce.isEmpty {
            dpopNonces[origin] = updatedNonce

            // RFC 9449 Section 8: Automatically retry once when server challenges with a fresh DPoP-Nonce on 401.
            if firstResponse.statusCode == 401 && activeToken != nil && updatedNonce != initialNonce {
                return try await sendOnce(
                    method: method,
                    url: url,
                    headers: headers,
                    body: body,
                    etagMatch: etagMatch,
                    token: activeToken,
                    nonce: updatedNonce
                )
            }
        }

        return (firstData, firstResponse)
    }

    private func sendOnce(
        method: String,
        url: URL,
        headers: [String: String],
        body: Data?,
        etagMatch: ETagMatch,
        token: String?,
        nonce: String?
    ) async throws -> (Data, HTTPURLResponse) {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body

        for (key, value) in headers {
            request.setValue(value, forHTTPHeaderField: key)
        }
        etagMatch.apply(to: &request)

        if let token, !token.isEmpty {
            let proof = try dpopSigner.signProof(
                httpMethod: method,
                url: url,
                accessToken: token,
                nonce: nonce
            )
            request.setValue("DPoP \(token)", forHTTPHeaderField: "Authorization")
            request.setValue(proof, forHTTPHeaderField: "DPoP")
        }

        let data: Data
        let urlResponse: URLResponse
        do {
            (data, urlResponse) = try await session.data(
                for: request,
                delegate: NoRedirectSessionDelegate.shared
            )
        } catch {
            throw WolinError.transportError(error.localizedDescription)
        }

        guard let httpResponse = urlResponse as? HTTPURLResponse else {
            throw WolinError.transportError("Non-HTTP response received for '\(url.absoluteString)'")
        }
        return (data, httpResponse)
    }

    private func validateSuccessStatus(
        response: HTTPURLResponse,
        data: Data,
        requestURL: URL
    ) throws {
        let code = response.statusCode
        if (200...299).contains(code) {
            return
        }

        let bodyMessage = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let message: String
        if let bodyMessage, !bodyMessage.isEmpty {
            message = bodyMessage
        } else {
            message = HTTPURLResponse.localizedString(forStatusCode: code)
        }

        switch code {
        case 401:
            let nonce = response.value(forHTTPHeaderField: "DPoP-Nonce")
            throw WolinError.unauthorized(message: message, dpopNonce: nonce)
        case 403:
            throw WolinError.forbidden(message: message)
        case 404:
            throw WolinError.notFound(url: requestURL)
        case 409:
            throw WolinError.conflict(message: message)
        case 412, 428:
            throw WolinError.preconditionFailed(statusCode: code, message: message)
        default:
            throw WolinError.httpError(statusCode: code, message: message)
        }
    }

    private func buildPodResource(
        url: URL,
        response: HTTPURLResponse,
        data: Data,
        fallbackResponse: HTTPURLResponse? = nil
    ) -> PodResource {
        let contentType = response.value(forHTTPHeaderField: "Content-Type")
        let etag = response.value(forHTTPHeaderField: "ETag")
            ?? fallbackResponse?.value(forHTTPHeaderField: "ETag")
        let wacAllow = response.value(forHTTPHeaderField: "WAC-Allow")
            ?? fallbackResponse?.value(forHTTPHeaderField: "WAC-Allow")
        let linkHeader = response.value(forHTTPHeaderField: "Link")
            ?? fallbackResponse?.value(forHTTPHeaderField: "Link")
            ?? ""
        let relations = LinkRelation.parseAll(linkHeader)

        var typeIRIs = Set<String>()
        var aclURL: URL?
        var storageURL: URL?
        var inboxURL: URL?

        for rel in relations {
            let resolved = (try? WebIdParser.resolveIRI(rel.target, base: url.absoluteString)) ?? rel.target
            switch rel.rel {
            case "type":
                typeIRIs.insert(rel.target)
            case "acl":
                if aclURL == nil { aclURL = URL(string: resolved) }
            case SolidVocabulary.pimStorage:
                if storageURL == nil { storageURL = URL(string: resolved) }
            case SolidVocabulary.ldpInbox:
                if inboxURL == nil { inboxURL = URL(string: resolved) }
            default:
                break
            }
        }

        let kind: PodResourceKind
        if typeIRIs.contains(SolidVocabulary.ldpBasicContainer) || typeIRIs.contains(SolidVocabulary.ldpContainer) {
            kind = .container
        } else if typeIRIs.contains(SolidVocabulary.ldpNonRDFSource) {
            kind = .nonRdfSource
        } else if typeIRIs.contains(SolidVocabulary.ldpRDFSource) {
            kind = .rdfSource
        } else if url.path.hasSuffix("/") {
            kind = .container
        } else if let primaryMedia = contentType?.split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased(),
                  primaryMedia == "text/turtle" || primaryMedia == "application/ld+json" || primaryMedia == "application/n-triples" {
            kind = .rdfSource
        } else {
            kind = .nonRdfSource
        }

        var normalizedHeaders: [String: String] = [:]
        if let fallbackResponse {
            for fallbackKey in ["Link", "WAC-Allow", "ETag"] {
                if let fallbackVal = fallbackResponse.value(forHTTPHeaderField: fallbackKey) {
                    normalizedHeaders[fallbackKey] = fallbackVal
                }
            }
        }
        for (rawKey, rawValue) in response.allHeaderFields {
            if let k = rawKey as? String, let v = rawValue as? String {
                normalizedHeaders[k] = v
            }
        }

        return PodResource(
            url: url,
            statusCode: response.statusCode,
            contentType: contentType,
            etag: etag,
            kind: kind,
            aclURL: aclURL,
            storageURL: storageURL,
            inboxURL: inboxURL,
            wacAllow: wacAllow,
            headers: normalizedHeaders,
            data: data
        )
    }

    private func buildWriteResult(
        defaultURL: URL,
        response: HTTPURLResponse
    ) -> PodWriteResult {
        let etag = response.value(forHTTPHeaderField: "ETag")
        var locationURL: URL?
        if let rawLocation = response.value(forHTTPHeaderField: "Location") {
            let resolved = (try? WebIdParser.resolveIRI(rawLocation, base: defaultURL.absoluteString)) ?? rawLocation
            locationURL = URL(string: resolved)
        }
        return PodWriteResult(
            url: locationURL ?? defaultURL,
            statusCode: response.statusCode,
            etag: etag,
            location: locationURL
        )
    }

    private func originKey(for url: URL) -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let scheme = components.scheme?.lowercased(),
              let host = components.host?.lowercased() else {
            return url.host ?? url.absoluteString
        }
        if let port = components.port {
            let isDefault = (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
            if !isDefault {
                return "\(scheme)://\(host):\(port)"
            }
        }
        return "\(scheme)://\(host)"
    }
}
