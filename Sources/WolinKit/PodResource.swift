// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Entropy Paradox, Inc. (https://wolin.id)

import Foundation

/// Standard W3C Solid, LDP, PIM, RDF, and FOAF vocabulary IRIs used by Wolin Pods.
public enum SolidVocabulary: Sendable {
    public static let rdfType = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
    public static let rdfFirst = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first"
    public static let rdfRest = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest"
    public static let rdfNil = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil"

    public static let ldpResource = "http://www.w3.org/ns/ldp#Resource"
    public static let ldpRDFSource = "http://www.w3.org/ns/ldp#RDFSource"
    public static let ldpNonRDFSource = "http://www.w3.org/ns/ldp#NonRDFSource"
    public static let ldpContainer = "http://www.w3.org/ns/ldp#Container"
    public static let ldpBasicContainer = "http://www.w3.org/ns/ldp#BasicContainer"
    public static let ldpContains = "http://www.w3.org/ns/ldp#contains"
    public static let ldpInbox = "http://www.w3.org/ns/ldp#inbox"

    public static let pimStorage = "http://www.w3.org/ns/pim/space#storage"
    public static let pimStorageType = "http://www.w3.org/ns/pim/space#Storage"
    public static let solidOidcIssuer = "http://www.w3.org/ns/solid/terms#oidcIssuer"

    public static let foafName = "http://xmlns.com/foaf/0.1/name"
    public static let foafPrimaryTopic = "http://xmlns.com/foaf/0.1/primaryTopic"
}

/// Classification of a Solid Linked Data Platform (LDP) resource.
public enum PodResourceKind: String, Sendable, Equatable, Codable {
    case container
    case rdfSource
    case nonRdfSource
}

/// Conditional HTTP ETag matching policy (`If-Match` / `If-None-Match`) for optimistic concurrency control.
public enum ETagMatch: Sendable, Equatable {
    /// Do not attach any ETag precondition header.
    case any
    /// Require the remote resource to match the specified ETag (`If-Match`).
    case ifMatch(String)
    /// Require the remote resource not to match the specified ETag (`If-None-Match`).
    case ifNoneMatch(String)

    /// Require that the target resource does not yet exist (`If-None-Match: *`).
    public static let createOnly: ETagMatch = .ifNoneMatch("*")

    func apply(to request: inout URLRequest) {
        switch self {
        case .any:
            break
        case .ifMatch(let tag):
            request.setValue(tag, forHTTPHeaderField: "If-Match")
        case .ifNoneMatch(let tag):
            request.setValue(tag, forHTTPHeaderField: "If-None-Match")
        }
    }
}

/// Parsed RFC 8288 HTTP `Link` header relation.
public struct LinkRelation: Sendable, Equatable {
    public let target: String
    public let rel: String

    public init(target: String, rel: String) {
        self.target = target
        self.rel = rel
    }

    /// Parses one or more RFC 8288 `Link` header values into `(target, rel)` pairs.
    public static func parseAll(_ headerValue: String) -> [LinkRelation] {
        let entries = splitLinkEntries(headerValue)
        var relations: [LinkRelation] = []

        for entry in entries {
            let trimmed = entry.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.hasPrefix("<"),
                  let closingBracket = trimmed.firstIndex(of: ">") else {
                continue
            }
            let targetStart = trimmed.index(after: trimmed.startIndex)
            let target = String(trimmed[targetStart..<closingBracket])
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !target.isEmpty else { continue }

            let paramsSlice = trimmed[trimmed.index(after: closingBracket)...]
            for rawParam in splitSemicolonParameters(String(paramsSlice)) {
                let param = rawParam.trimmingCharacters(in: .whitespacesAndNewlines)
                guard let eqIdx = param.firstIndex(of: "=") else { continue }
                let key = param[..<eqIdx]
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                    .lowercased()
                guard key == "rel" else { continue }
                var val = String(param[param.index(after: eqIdx)...])
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if val.hasPrefix("\"") && val.hasSuffix("\"") && val.count >= 2 {
                    val.removeFirst()
                    val.removeLast()
                }
                for relToken in val.split(whereSeparator: { $0.isWhitespace }) {
                    relations.append(LinkRelation(target: target, rel: String(relToken)))
                }
            }
        }

        return relations
    }

    private static func splitLinkEntries(_ raw: String) -> [String] {
        var results: [String] = []
        var current = ""
        var inQuotes = false
        var inBrackets = false
        var escaped = false

        for ch in raw {
            if escaped {
                current.append(ch)
                escaped = false
                continue
            }
            if ch == "\\" && inQuotes {
                current.append(ch)
                escaped = true
                continue
            }
            if ch == "\"" && !inBrackets {
                inQuotes.toggle()
                current.append(ch)
                continue
            }
            if !inQuotes {
                if ch == "<" {
                    inBrackets = true
                } else if ch == ">" {
                    inBrackets = false
                } else if ch == "," && !inBrackets {
                    results.append(current)
                    current = ""
                    continue
                }
            }
            current.append(ch)
        }
        if !current.isEmpty {
            results.append(current)
        }
        return results
    }

    private static func splitSemicolonParameters(_ raw: String) -> [String] {
        var results: [String] = []
        var current = ""
        var inQuotes = false
        var escaped = false

        for ch in raw {
            if escaped {
                current.append(ch)
                escaped = false
                continue
            }
            if ch == "\\" && inQuotes {
                current.append(ch)
                escaped = true
                continue
            }
            if ch == "\"" {
                inQuotes.toggle()
                current.append(ch)
                continue
            }
            if ch == ";" && !inQuotes {
                if !current.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    results.append(current)
                }
                current = ""
                continue
            }
            current.append(ch)
        }
        if !current.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            results.append(current)
        }
        return results
    }
}

/// Representation of a retrieved Solid Pod LDP resource (`GET` or `HEAD`).
public struct PodResource: Sendable, Equatable {
    public let url: URL
    public let statusCode: Int
    public let contentType: String?
    public let etag: String?
    public let kind: PodResourceKind
    public let aclURL: URL?
    public let storageURL: URL?
    public let inboxURL: URL?
    public let wacAllow: String?
    public let headers: [String: String]
    public let data: Data

    public init(
        url: URL,
        statusCode: Int,
        contentType: String?,
        etag: String?,
        kind: PodResourceKind,
        aclURL: URL? = nil,
        storageURL: URL? = nil,
        inboxURL: URL? = nil,
        wacAllow: String? = nil,
        headers: [String: String] = [:],
        data: Data = Data()
    ) {
        self.url = url
        self.statusCode = statusCode
        self.contentType = contentType
        self.etag = etag
        self.kind = kind
        self.aclURL = aclURL
        self.storageURL = storageURL
        self.inboxURL = inboxURL
        self.wacAllow = wacAllow
        self.headers = headers
        self.data = data
    }

    /// UTF-8 decoded body string, if valid UTF-8.
    public var text: String? {
        String(data: data, encoding: .utf8)
    }

    /// Decodes the resource body from JSON into the given `Decodable` type.
    public func decodeJSON<T: Decodable>(
        _ type: T.Type,
        decoder: JSONDecoder = JSONDecoder()
    ) throws -> T {
        try decoder.decode(T.self, from: data)
    }
}

/// Metadata returned from mutating Solid LDP operations (`PUT`, `POST`, `PATCH`).
public struct PodWriteResult: Sendable, Equatable {
    public let url: URL
    public let statusCode: Int
    public let etag: String?
    public let location: URL?

    public var created: Bool {
        statusCode == 201
    }

    public init(url: URL, statusCode: Int, etag: String?, location: URL?) {
        self.url = url
        self.statusCode = statusCode
        self.etag = etag
        self.location = location
    }
}

/// Typed errors emitted by `WolinKit`.
public enum WolinError: Error, LocalizedError, Sendable, Equatable {
    case invalidURL(String)
    case invalidDPoPTarget(String)
    case cryptographyError(String)
    case invalidWebIDProfile(String)
    case storageNotFound(webID: String)
    case notModified(etag: String?)
    case preconditionFailed(statusCode: Int, message: String)
    case unauthorized(message: String, dpopNonce: String?)
    case forbidden(message: String)
    case notFound(url: URL)
    case conflict(message: String)
    case httpError(statusCode: Int, message: String)
    case transportError(String)

    public var errorDescription: String? {
        switch self {
        case .invalidURL(let raw):
            return "Invalid URL: \(raw)"
        case .invalidDPoPTarget(let reason):
            return "Invalid RFC 9449 DPoP target: \(reason)"
        case .cryptographyError(let reason):
            return "Cryptographic operation failed: \(reason)"
        case .invalidWebIDProfile(let reason):
            return "Invalid Solid WebID Profile RDF document: \(reason)"
        case .storageNotFound(let webID):
            return "No pim:storage triple or Link relation discovered for WebID '\(webID)'"
        case .notModified(let etag):
            return "Resource not modified (HTTP 304, ETag: \(etag ?? "none"))"
        case .preconditionFailed(let code, let message):
            return "ETag precondition failed (HTTP \(code)): \(message)"
        case .unauthorized(let message, _):
            return "Unauthorized (HTTP 401): \(message)"
        case .forbidden(let message):
            return "Forbidden (HTTP 403): \(message)"
        case .notFound(let url):
            return "LDP resource not found (HTTP 404): \(url.absoluteString)"
        case .conflict(let message):
            return "LDP conflict (HTTP 409): \(message)"
        case .httpError(let statusCode, let message):
            return "HTTP \(statusCode): \(message)"
        case .transportError(let reason):
            return "HTTP transport error: \(reason)"
        }
    }
}
