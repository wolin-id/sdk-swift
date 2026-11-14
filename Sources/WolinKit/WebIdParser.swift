// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Entropy Paradox, Inc. (https://wolin.id)

import Foundation

/// An RDF term extracted from a W3C Turtle document.
public enum RDFTerm: Sendable, Equatable {
    case iri(String)
    case blankNode(String)
    case literal(value: String, datatype: String?, language: String?)
}

/// An RDF triple `(subject, predicate, object)` extracted from a W3C Turtle document.
public struct RDFTriple: Sendable, Equatable {
    public let subject: RDFTerm
    public let predicate: String
    public let object: RDFTerm

    public init(subject: RDFTerm, predicate: String, object: RDFTerm) {
        self.subject = subject
        self.predicate = predicate
        self.object = object
    }
}

/// Parsed W3C Solid WebID Profile metadata (`solid:oidcIssuer`, `pim:storage`, `ldp:inbox`, `foaf:name`).
public struct WebIdProfile: Sendable, Equatable, Codable {
    public let webID: String
    public let types: [String]
    public let name: String?
    public let oidcIssuers: [String]
    public let storages: [String]
    public let inboxes: [String]

    public init(
        webID: String,
        types: [String] = [],
        name: String? = nil,
        oidcIssuers: [String] = [],
        storages: [String] = [],
        inboxes: [String] = []
    ) {
        self.webID = webID
        self.types = types
        self.name = name
        self.oidcIssuers = oidcIssuers
        self.storages = storages
        self.inboxes = inboxes
    }

    /// Primary Solid Pod root URL (`pim:storage`), if present.
    public var primaryStorageURL: URL? {
        storages.lazy.compactMap(URL.init(string:)).first
    }

    /// Primary Solid-OIDC identity provider URL (`solid:oidcIssuer`), if present.
    public var primaryOIDCIssuerURL: URL? {
        oidcIssuers.lazy.compactMap(URL.init(string:)).first
    }

    /// Primary Linked Data Notifications inbox URL (`ldp:inbox`), if present.
    public var primaryInboxURL: URL? {
        inboxes.lazy.compactMap(URL.init(string:)).first
    }

    /// Verifies the W3C Solid-OIDC trust chain (`<webID> solid:oidcIssuer <issuer>`).
    public func authorizes(oidcIssuer: String) -> Bool {
        let trimmed = oidcIssuer.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        return oidcIssuers.contains(trimmed)
    }
}

/// Pure-Swift W3C RDF 1.1 Turtle parser tailored for Solid WebID Profiles and LDP Containers.
public enum WebIdParser: Sendable {
    public static let maxProfileBytes = 512 * 1024

    /// Parses a Solid WebID Profile Turtle document and extracts metadata for `webID`.
    public static func parseTurtle(
        _ turtle: String,
        webID: String,
        baseIRI: String? = nil
    ) throws -> WebIdProfile {
        let cleanWebID = webID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanWebID.isEmpty else {
            throw WolinError.invalidWebIDProfile("WebID URI must not be empty")
        }
        guard turtle.utf8.count <= maxProfileBytes else {
            throw WolinError.invalidWebIDProfile("WebID Profile RDF exceeds maximum size of \(maxProfileBytes) bytes")
        }

        let effectiveBase = baseIRI ?? stripFragment(from: cleanWebID)
        let triples = try parseTriples(turtle, baseIRI: effectiveBase)

        var types: [String] = []
        var seenTypes = Set<String>()
        var name: String?
        var oidcIssuers: [String] = []
        var seenIssuers = Set<String>()
        var storages: [String] = []
        var seenStorages = Set<String>()
        var inboxes: [String] = []
        var seenInboxes = Set<String>()

        for triple in triples {
            guard case .iri(let subj) = triple.subject, subj == cleanWebID else {
                continue
            }

            switch triple.predicate {
            case SolidVocabulary.rdfType:
                if case .iri(let typeIRI) = triple.object, seenTypes.insert(typeIRI).inserted {
                    types.append(typeIRI)
                }
            case SolidVocabulary.foafName:
                if name == nil, case .literal(let literalValue, _, _) = triple.object {
                    name = literalValue
                }
            case SolidVocabulary.solidOidcIssuer:
                if case .iri(let issuer) = triple.object, seenIssuers.insert(issuer).inserted {
                    oidcIssuers.append(issuer)
                }
            case SolidVocabulary.pimStorage:
                if case .iri(let storage) = triple.object, seenStorages.insert(storage).inserted {
                    storages.append(storage)
                }
            case SolidVocabulary.ldpInbox:
                if case .iri(let inbox) = triple.object, seenInboxes.insert(inbox).inserted {
                    inboxes.append(inbox)
                }
            default:
                break
            }
        }

        return WebIdProfile(
            webID: cleanWebID,
            types: types,
            name: name,
            oidcIssuers: oidcIssuers,
            storages: storages,
            inboxes: inboxes
        )
    }

    /// Extracts direct child resource URLs (`ldp:contains`) from a Solid LDP Container Turtle representation.
    public static func extractContainedURLs(_ turtle: String, containerURL: URL) throws -> [URL] {
        let base = stripFragment(from: containerURL.absoluteString)
        let triples = try parseTriples(turtle, baseIRI: base)
        var urls: [URL] = []
        var seen = Set<String>()
        for triple in triples {
            guard case .iri(let subj) = triple.subject,
                  subj == base,
                  triple.predicate == SolidVocabulary.ldpContains,
                  case .iri(let childIRI) = triple.object,
                  seen.insert(childIRI).inserted,
                  let childURL = URL(string: childIRI) else {
                continue
            }
            urls.append(childURL)
        }
        return urls
    }

    /// Parses a W3C Turtle document into RDF triples resolved against `baseIRI`.
    public static func parseTriples(_ turtle: String, baseIRI: String) throws -> [RDFTriple] {
        guard turtle.utf8.count <= maxProfileBytes else {
            throw WolinError.invalidWebIDProfile("Turtle payload exceeds maximum allowed size")
        }
        var tokenizer = TurtleTokenizer(turtle)
        let tokens = try tokenizer.tokenize()
        var parser = TurtleDocumentParser(tokens: tokens, baseIRI: stripFragment(from: baseIRI))
        return try parser.parse()
    }

    /// Resolves a relative or absolute IRI reference against a base IRI according to RFC 3986.
    public static func resolveIRI(_ reference: String, base: String) throws -> String {
        let docBase = stripFragment(from: base)
        guard !docBase.isEmpty else {
            throw WolinError.invalidWebIDProfile("Base IRI must not be empty")
        }

        if reference.isEmpty {
            return docBase
        }
        if reference.hasPrefix("#") {
            return docBase + reference
        }
        if hasURIScheme(reference) {
            return reference
        }

        guard let schemeSeparator = docBase.range(of: "://") else {
            throw WolinError.invalidWebIDProfile("Base IRI '\(docBase)' lacks '://' authority")
        }
        let scheme = String(docBase[..<schemeSeparator.lowerBound])
        let afterScheme = docBase[schemeSeparator.upperBound...]

        let authority: String
        let basePath: String
        if let firstSlash = afterScheme.firstIndex(of: "/") {
            authority = String(afterScheme[..<firstSlash])
            let pathAndQuery = String(afterScheme[firstSlash...])
            basePath = String(pathAndQuery.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first ?? "/")
        } else {
            authority = String(afterScheme)
            basePath = "/"
        }

        if reference.hasPrefix("//") {
            return "\(scheme):\(reference)"
        }

        let (refBeforeFragment, fragmentSuffix) = splitOnce(reference, separator: "#")
        let (refPath, querySuffix) = splitOnce(refBeforeFragment, separator: "?")

        if refPath.isEmpty {
            let effectiveQuery: String
            if !querySuffix.isEmpty {
                effectiveQuery = querySuffix
            } else if let qIdx = docBase.firstIndex(of: "?") {
                effectiveQuery = String(docBase[qIdx...])
            } else {
                effectiveQuery = ""
            }
            return "\(scheme)://\(authority)\(basePath)\(effectiveQuery)\(fragmentSuffix)"
        }

        let mergedPath: String
        if refPath.hasPrefix("/") {
            mergedPath = refPath
        } else {
            let baseDir: String
            if let lastSlash = basePath.lastIndex(of: "/") {
                baseDir = String(basePath[...lastSlash])
            } else {
                baseDir = "/"
            }
            mergedPath = baseDir + refPath
        }

        let normalizedPath = removeDotSegments(mergedPath)
        return "\(scheme)://\(authority)\(normalizedPath)\(querySuffix)\(fragmentSuffix)"
    }

    private static func stripFragment(from iri: String) -> String {
        if let idx = iri.firstIndex(of: "#") {
            return String(iri[..<idx])
        }
        return iri
    }

    private static func splitOnce(_ input: String, separator: Character) -> (String, String) {
        if let idx = input.firstIndex(of: separator) {
            return (String(input[..<idx]), String(input[idx...]))
        }
        return (input, "")
    }

    private static func hasURIScheme(_ value: String) -> Bool {
        guard let colonIdx = value.firstIndex(of: ":"), colonIdx != value.startIndex else {
            return false
        }
        let prefix = value[..<colonIdx]
        guard let first = prefix.unicodeScalars.first,
              CharacterSet.letters.contains(first) else {
            return false
        }
        for scalar in prefix.unicodeScalars.dropFirst() {
            let v = scalar.value
            let isAlphaNum = (v >= 0x30 && v <= 0x39) || (v >= 0x41 && v <= 0x5A) || (v >= 0x61 && v <= 0x7A)
            if !isAlphaNum && scalar != "+" && scalar != "-" && scalar != "." {
                return false
            }
        }
        return true
    }

    private static func removeDotSegments(_ path: String) -> String {
        let hasTrailingSlash = path.hasSuffix("/") || path.hasSuffix("/.") || path.hasSuffix("/..")
        let segments = path.split(separator: "/", omittingEmptySubsequences: false)
        var stack: [Substring] = []

        for (idx, seg) in segments.enumerated() {
            if idx == 0 && seg.isEmpty {
                continue
            }
            if seg == "." || seg.isEmpty {
                continue
            }
            if seg == ".." {
                if !stack.isEmpty {
                    stack.removeLast()
                }
            } else {
                stack.append(seg)
            }
        }

        if stack.isEmpty {
            return "/"
        }
        var result = "/" + stack.joined(separator: "/")
        if hasTrailingSlash && !result.hasSuffix("/") {
            result.append("/")
        }
        return result
    }
}

// MARK: - Internal Turtle Lexer & Parser

private enum TurtleToken: Equatable {
    case directivePrefix          // @prefix
    case directiveBase            // @base
    case sparqlPrefix             // PREFIX (case-insensitive)
    case sparqlBase               // BASE (case-insensitive)
    case iriRef(String)           // <...>
    case prefixedName(String, String) // prefix:local
    case blankNodeLabel(String)   // _:label
    case stringLiteral(String)    // "...", '...', """...""", '''...'''
    case langTag(String)          // @en
    case datatypeMarker           // ^^
    case numberLiteral(String, String) // (lexical, datatypeIRI)
    case booleanLiteral(String)   // "true" / "false"
    case keywordA                 // a
    case dot                      // .
    case semicolon                // ;
    case comma                    // ,
    case lBracket                 // [
    case rBracket                 // ]
    case lParen                   // (
    case rParen                   // )
}

private struct TurtleTokenizer {
    private static let xsdInteger = "http://www.w3.org/2001/XMLSchema#integer"
    private static let xsdDecimal = "http://www.w3.org/2001/XMLSchema#decimal"
    private static let xsdDouble = "http://www.w3.org/2001/XMLSchema#double"

    private let scalars: [UnicodeScalar]
    private var index: Int = 0

    init(_ source: String) {
        self.scalars = Array(source.unicodeScalars)
    }

    mutating func tokenize() throws -> [TurtleToken] {
        var tokens: [TurtleToken] = []

        while index < scalars.count {
            skipWhitespaceAndComments()
            guard index < scalars.count else { break }

            let ch = scalars[index]

            switch ch {
            case "<":
                tokens.append(.iriRef(try readIRIRef()))

            case "\"", "'":
                let str = try readStringLiteral()
                tokens.append(.stringLiteral(str))
                // Immediately check for optional @lang or ^^datatype without skipping comments into unrelated tokens
                if index < scalars.count && scalars[index] == "@" {
                    index += 1
                    let lang = try readLanguageTag()
                    tokens.append(.langTag(lang))
                } else if index + 1 < scalars.count && scalars[index] == "^" && scalars[index + 1] == "^" {
                    index += 2
                    tokens.append(.datatypeMarker)
                }

            case "@":
                index += 1
                let word = readAlphaTag()
                if word == "prefix" {
                    tokens.append(.directivePrefix)
                } else if word == "base" {
                    tokens.append(.directiveBase)
                } else {
                    throw WolinError.invalidWebIDProfile("Unknown Turtle '@' directive '@\(word)'")
                }

            case ";":
                index += 1
                tokens.append(.semicolon)

            case ",":
                index += 1
                tokens.append(.comma)

            case "[":
                index += 1
                tokens.append(.lBracket)

            case "]":
                index += 1
                tokens.append(.rBracket)

            case "(":
                index += 1
                tokens.append(.lParen)

            case ")":
                index += 1
                tokens.append(.rParen)

            case ".":
                if index + 1 < scalars.count && isDigit(scalars[index + 1]) {
                    let (num, dt) = readNumericLiteral()
                    tokens.append(.numberLiteral(num, dt))
                } else {
                    index += 1
                    tokens.append(.dot)
                }

            case "+", "-":
                if index + 1 < scalars.count && (isDigit(scalars[index + 1]) || scalars[index + 1] == ".") {
                    let (num, dt) = readNumericLiteral()
                    tokens.append(.numberLiteral(num, dt))
                } else {
                    throw WolinError.invalidWebIDProfile("Unexpected character '\(ch)' in Turtle input")
                }

            case "_" where index + 1 < scalars.count && scalars[index + 1] == ":":
                index += 2
                let label = try readBlankNodeLabel()
                tokens.append(.blankNodeLabel(label))

            default:
                if isDigit(ch) {
                    let (num, dt) = readNumericLiteral()
                    tokens.append(.numberLiteral(num, dt))
                } else {
                    tokens.append(try readWordOrPrefixedName())
                }
            }
        }

        return tokens
    }

    private mutating func skipWhitespaceAndComments() {
        while index < scalars.count {
            let s = scalars[index]
            if isWhitespace(s) {
                index += 1
            } else if s == "#" {
                while index < scalars.count && scalars[index] != "\n" && scalars[index] != "\r" {
                    index += 1
                }
            } else {
                break
            }
        }
    }

    private mutating func readIRIRef() throws -> String {
        index += 1 // consume '<'
        var out = String.UnicodeScalarView()

        while index < scalars.count {
            let ch = scalars[index]
            if ch == ">" {
                index += 1
                return String(out)
            }
            if ch == "<" || ch == "\"" || ch == "{" || ch == "}" || ch == "|" || ch == "^" || ch == "`" || ch.value <= 0x20 {
                throw WolinError.invalidWebIDProfile("Illegal character in Turtle <IRIREF>")
            }
            if ch == "\\" {
                index += 1
                let escaped = try readUnicodeEscapeOnly()
                out.append(escaped)
            } else {
                out.append(ch)
                index += 1
            }
        }
        throw WolinError.invalidWebIDProfile("Unterminated '<IRIREF>' in Turtle document")
    }

    private mutating func readStringLiteral() throws -> String {
        let quote = scalars[index]
        let isLong: Bool
        if index + 2 < scalars.count && scalars[index + 1] == quote && scalars[index + 2] == quote {
            isLong = true
            index += 3
        } else {
            isLong = false
            index += 1
        }

        var out = String.UnicodeScalarView()
        while index < scalars.count {
            let ch = scalars[index]
            if isLong {
                if index + 2 < scalars.count && ch == quote && scalars[index + 1] == quote && scalars[index + 2] == quote {
                    index += 3
                    return String(out)
                }
            } else {
                if ch == quote {
                    index += 1
                    return String(out)
                }
                if ch == "\n" || ch == "\r" {
                    throw WolinError.invalidWebIDProfile("Unescaped newline inside single-line Turtle string literal")
                }
            }

            if ch == "\\" {
                index += 1
                out.append(try readStringEscape())
            } else {
                out.append(ch)
                index += 1
            }
        }

        throw WolinError.invalidWebIDProfile("Unterminated string literal in Turtle document")
    }

    private mutating func readStringEscape() throws -> UnicodeScalar {
        guard index < scalars.count else {
            throw WolinError.invalidWebIDProfile("Trailing backslash in Turtle string literal")
        }
        let esc = scalars[index]
        switch esc {
        case "t": index += 1; return "\t"
        case "b": index += 1; return "\u{0008}"
        case "n": index += 1; return "\n"
        case "r": index += 1; return "\r"
        case "f": index += 1; return "\u{000C}"
        case "\"": index += 1; return "\""
        case "'": index += 1; return "'"
        case "\\": index += 1; return "\\"
        case "u", "U":
            return try readUnicodeEscapeOnly()
        default:
            throw WolinError.invalidWebIDProfile("Invalid string escape '\\\(esc)' in Turtle literal")
        }
    }

    private mutating func readUnicodeEscapeOnly() throws -> UnicodeScalar {
        guard index < scalars.count else {
            throw WolinError.invalidWebIDProfile("Truncated unicode escape in Turtle")
        }
        let kind = scalars[index]
        let digits = kind == "u" ? 4 : (kind == "U" ? 8 : 0)
        guard digits > 0, index + digits < scalars.count else {
            throw WolinError.invalidWebIDProfile("Invalid unicode escape sequence in Turtle")
        }
        index += 1
        var hex = ""
        for _ in 0..<digits {
            hex.unicodeScalars.append(scalars[index])
            index += 1
        }
        guard let codePoint = UInt32(hex, radix: 16),
              let scalar = UnicodeScalar(codePoint) else {
            throw WolinError.invalidWebIDProfile("Invalid unicode scalar '\\\(kind)\(hex)' in Turtle")
        }
        return scalar
    }

    private mutating func readAlphaTag() -> String {
        var out = String.UnicodeScalarView()
        while index < scalars.count {
            let s = scalars[index]
            if (s.value >= 0x41 && s.value <= 0x5A) || (s.value >= 0x61 && s.value <= 0x7A) {
                out.append(s)
                index += 1
            } else {
                break
            }
        }
        return String(out)
    }

    private mutating func readLanguageTag() throws -> String {
        var out = String.UnicodeScalarView()
        while index < scalars.count {
            let s = scalars[index]
            let isAlpha = (s.value >= 0x41 && s.value <= 0x5A) || (s.value >= 0x61 && s.value <= 0x7A)
            let isNum = s.value >= 0x30 && s.value <= 0x39
            if isAlpha || (out.count > 0 && (isNum || s == "-")) {
                out.append(s)
                index += 1
            } else {
                break
            }
        }
        let tag = String(out)
        guard !tag.isEmpty, !tag.hasSuffix("-") else {
            throw WolinError.invalidWebIDProfile("Malformed language tag in Turtle literal")
        }
        return tag
    }

    private mutating func readBlankNodeLabel() throws -> String {
        let start = index
        while index < scalars.count {
            let s = scalars[index]
            if isPNChar(s) || s == "." {
                index += 1
            } else {
                break
            }
        }
        while index > start && scalars[index - 1] == "." {
            index -= 1
        }
        guard index > start else {
            throw WolinError.invalidWebIDProfile("Empty blank node label '_:' in Turtle")
        }
        return String(String.UnicodeScalarView(scalars[start..<index]))
    }

    private mutating func readNumericLiteral() -> (String, String) {
        let start = index
        var hasDot = false
        var hasExp = false

        if scalars[index] == "+" || scalars[index] == "-" {
            index += 1
        }
        while index < scalars.count && isDigit(scalars[index]) {
            index += 1
        }
        if index < scalars.count && scalars[index] == "." {
            // Only consume '.' as decimal point if followed by a digit or exponent; otherwise leave '.' as statement terminator!
            if index + 1 < scalars.count && (isDigit(scalars[index + 1]) || scalars[index + 1] == "e" || scalars[index + 1] == "E") {
                hasDot = true
                index += 1
                while index < scalars.count && isDigit(scalars[index]) {
                    index += 1
                }
            } else if start < index && (scalars[start] == "." || (index == start + 1 && (scalars[start] == "+" || scalars[start] == "-"))) {
                hasDot = true
                index += 1
                while index < scalars.count && isDigit(scalars[index]) {
                    index += 1
                }
            }
        }
        if index < scalars.count && (scalars[index] == "e" || scalars[index] == "E") {
            hasExp = true
            index += 1
            if index < scalars.count && (scalars[index] == "+" || scalars[index] == "-") {
                index += 1
            }
            while index < scalars.count && isDigit(scalars[index]) {
                index += 1
            }
        }

        let lexical = String(String.UnicodeScalarView(scalars[start..<index]))
        let datatype = hasExp ? Self.xsdDouble : (hasDot ? Self.xsdDecimal : Self.xsdInteger)
        return (lexical, datatype)
    }

    private mutating func readWordOrPrefixedName() throws -> TurtleToken {
        // Empty prefix `:local` or `:`
        if scalars[index] == ":" {
            index += 1
            let local = try readPNLocal()
            return .prefixedName("", local)
        }

        let prefixStart = index
        guard isPNCharsBase(scalars[index]) else {
            throw WolinError.invalidWebIDProfile("Unexpected character '\(scalars[index])' in Turtle document")
        }
        index += 1
        while index < scalars.count && (isPNChar(scalars[index]) || scalars[index] == ".") {
            index += 1
        }
        // W3C Turtle Rule [167s]: PN_PREFIX cannot end with '.'
        while index > prefixStart && scalars[index - 1] == "." {
            index -= 1
        }

        let word = String(String.UnicodeScalarView(scalars[prefixStart..<index]))
        if index < scalars.count && scalars[index] == ":" {
            index += 1
            let local = try readPNLocal()
            return .prefixedName(word, local)
        }

        switch word {
        case "a":
            return .keywordA
        case "true", "false":
            return .booleanLiteral(word)
        default:
            let upper = word.uppercased()
            if upper == "PREFIX" {
                return .sparqlPrefix
            } else if upper == "BASE" {
                return .sparqlBase
            }
            throw WolinError.invalidWebIDProfile("Unexpected bare identifier '\(word)' in Turtle document")
        }
    }

    private mutating func readPNLocal() throws -> String {
        var out = String.UnicodeScalarView()
        var trailingUnescapedDots = 0

        while index < scalars.count {
            let s = scalars[index]
            if s == "\\" {
                guard index + 1 < scalars.count else {
                    throw WolinError.invalidWebIDProfile("Trailing backslash in prefixed name")
                }
                let escaped = scalars[index + 1]
                out.append(escaped)
                trailingUnescapedDots = 0
                index += 2
            } else if isPNChar(s) || s == ":" || s == "%" {
                out.append(s)
                trailingUnescapedDots = 0
                index += 1
            } else if s == "." {
                out.append(s)
                trailingUnescapedDots += 1
                index += 1
            } else {
                break
            }
        }

        // W3C Turtle Rule [168s]: unescaped '.' cannot end PN_LOCAL; rewind so '.' tokenizes as statement terminator.
        if trailingUnescapedDots > 0 {
            index -= trailingUnescapedDots
            let keepCount = out.count - trailingUnescapedDots
            out = String.UnicodeScalarView(out.prefix(keepCount))
        }

        return String(out)
    }

    private func isWhitespace(_ s: UnicodeScalar) -> Bool {
        s == " " || s == "\t" || s == "\n" || s == "\r"
    }

    private func isDigit(_ s: UnicodeScalar) -> Bool {
        s.value >= 0x30 && s.value <= 0x39
    }

    private func isPNCharsBase(_ s: UnicodeScalar) -> Bool {
        let v = s.value
        return (v >= 0x41 && v <= 0x5A)
            || (v >= 0x61 && v <= 0x7A)
            || (v >= 0x00C0 && v <= 0x00D6)
            || (v >= 0x00D8 && v <= 0x00F6)
            || (v >= 0x00F8 && v <= 0x02FF)
            || (v >= 0x0370 && v <= 0x037D)
            || (v >= 0x037F && v <= 0x1FFF)
            || (v >= 0x200C && v <= 0x200D)
            || (v >= 0x2070 && v <= 0x218F)
            || (v >= 0x2C00 && v <= 0x2FEF)
            || (v >= 0x3001 && v <= 0xD7FF)
            || (v >= 0xF900 && v <= 0xFDCF)
            || (v >= 0xFDF0 && v <= 0xFFFD)
            || (v >= 0x10000 && v <= 0xEFFFF)
    }

    private func isPNChar(_ s: UnicodeScalar) -> Bool {
        let v = s.value
        return isPNCharsBase(s)
            || s == "_"
            || s == "-"
            || isDigit(s)
            || v == 0x00B7
            || (v >= 0x0300 && v <= 0x036F)
            || (v >= 0x203F && v <= 0x2040)
    }
}

private struct TurtleDocumentParser {
    private static let xsdString = "http://www.w3.org/2001/XMLSchema#string"
    private static let xsdBoolean = "http://www.w3.org/2001/XMLSchema#boolean"
    private static let rdfLangString = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString"

    private let tokens: [TurtleToken]
    private var cursor: Int = 0
    private var baseIRI: String
    private var prefixes: [String: String] = [:]
    private var blankCounter: Int = 0
    private var triples: [RDFTriple] = []

    init(tokens: [TurtleToken], baseIRI: String) {
        self.tokens = tokens
        self.baseIRI = baseIRI
    }

    mutating func parse() throws -> [RDFTriple] {
        while cursor < tokens.count {
            switch tokens[cursor] {
            case .directivePrefix:
                cursor += 1
                try parsePrefixDirective(requiresDot: true)
            case .sparqlPrefix:
                cursor += 1
                try parsePrefixDirective(requiresDot: false)
            case .directiveBase:
                cursor += 1
                try parseBaseDirective(requiresDot: true)
            case .sparqlBase:
                cursor += 1
                try parseBaseDirective(requiresDot: false)
            default:
                try parseTriplesStatement()
            }
        }
        return triples
    }

    private mutating func parsePrefixDirective(requiresDot: Bool) throws {
        guard cursor < tokens.count,
              case .prefixedName(let prefixName, let local) = tokens[cursor],
              local.isEmpty else {
            throw WolinError.invalidWebIDProfile("Expected prefix name in Turtle prefix directive")
        }
        cursor += 1

        guard cursor < tokens.count, case .iriRef(let rawIRI) = tokens[cursor] else {
            throw WolinError.invalidWebIDProfile("Expected <IRI> in Turtle prefix directive")
        }
        cursor += 1

        let resolvedNamespace = try WebIdParser.resolveIRI(rawIRI, base: baseIRI)
        prefixes[prefixName] = resolvedNamespace

        if requiresDot {
            try expectToken(.dot, context: "@prefix directive")
        }
    }

    private mutating func parseBaseDirective(requiresDot: Bool) throws {
        guard cursor < tokens.count, case .iriRef(let rawBase) = tokens[cursor] else {
            throw WolinError.invalidWebIDProfile("Expected <IRI> in Turtle base directive")
        }
        cursor += 1

        baseIRI = try WebIdParser.resolveIRI(rawBase, base: baseIRI)

        if requiresDot {
            try expectToken(.dot, context: "@base directive")
        }
    }

    private mutating func parseTriplesStatement() throws {
        guard cursor < tokens.count else { return }

        // W3C Turtle Rule [6]: `triples ::= subject predicateObjectList | blankNodePropertyList predicateObjectList?`
        if tokens[cursor] == .lBracket {
            let (bnode, hadInnerPredicates) = try parseBlankNodePropertyList()
            if cursor < tokens.count && tokens[cursor] != .dot {
                try parsePredicateObjectList(subject: bnode)
            } else if !hadInnerPredicates {
                throw WolinError.invalidWebIDProfile("Empty '[]' subject requires predicateObjectList")
            }
            try expectToken(.dot, context: "blankNodePropertyList statement")
            return
        }

        let subject = try parseSubject()
        try parsePredicateObjectList(subject: subject)
        try expectToken(.dot, context: "triple statement")
    }

    private mutating func parseSubject() throws -> RDFTerm {
        guard cursor < tokens.count else {
            throw WolinError.invalidWebIDProfile("Unexpected end of Turtle input while expecting subject")
        }
        switch tokens[cursor] {
        case .iriRef, .prefixedName:
            return .iri(try parseIRI())
        case .blankNodeLabel(let label):
            cursor += 1
            return .blankNode(label)
        case .lParen:
            return try parseCollection()
        default:
            throw WolinError.invalidWebIDProfile("Invalid Turtle subject token")
        }
    }

    private mutating func parsePredicateObjectList(subject: RDFTerm) throws {
        let firstPred = try parseVerb()
        try parseObjectList(subject: subject, predicate: firstPred)

        while cursor < tokens.count && tokens[cursor] == .semicolon {
            while cursor < tokens.count && tokens[cursor] == .semicolon {
                cursor += 1
            }
            if cursor >= tokens.count || tokens[cursor] == .dot || tokens[cursor] == .rBracket {
                break
            }
            let nextPred = try parseVerb()
            try parseObjectList(subject: subject, predicate: nextPred)
        }
    }

    private mutating func parseVerb() throws -> String {
        guard cursor < tokens.count else {
            throw WolinError.invalidWebIDProfile("Unexpected end of Turtle input while expecting predicate")
        }
        if tokens[cursor] == .keywordA {
            cursor += 1
            return SolidVocabulary.rdfType
        }
        return try parseIRI()
    }

    private mutating func parseObjectList(subject: RDFTerm, predicate: String) throws {
        let firstObj = try parseObject()
        triples.append(RDFTriple(subject: subject, predicate: predicate, object: firstObj))

        while cursor < tokens.count && tokens[cursor] == .comma {
            cursor += 1
            let nextObj = try parseObject()
            triples.append(RDFTriple(subject: subject, predicate: predicate, object: nextObj))
        }
    }

    private mutating func parseObject() throws -> RDFTerm {
        guard cursor < tokens.count else {
            throw WolinError.invalidWebIDProfile("Unexpected end of Turtle input while expecting object")
        }

        switch tokens[cursor] {
        case .iriRef, .prefixedName:
            return .iri(try parseIRI())

        case .blankNodeLabel(let label):
            cursor += 1
            return .blankNode(label)

        case .lBracket:
            let (bnode, _) = try parseBlankNodePropertyList()
            return bnode

        case .lParen:
            return try parseCollection()

        case .stringLiteral(let lexical):
            cursor += 1
            if cursor < tokens.count, case .langTag(let lang) = tokens[cursor] {
                cursor += 1
                return .literal(value: lexical, datatype: Self.rdfLangString, language: lang.lowercased())
            }
            if cursor < tokens.count, tokens[cursor] == .datatypeMarker {
                cursor += 1
                let dtIRI = try parseIRI()
                return .literal(value: lexical, datatype: dtIRI, language: nil)
            }
            return .literal(value: lexical, datatype: Self.xsdString, language: nil)

        case .numberLiteral(let lexical, let dt):
            cursor += 1
            return .literal(value: lexical, datatype: dt, language: nil)

        case .booleanLiteral(let lexical):
            cursor += 1
            return .literal(value: lexical, datatype: Self.xsdBoolean, language: nil)

        default:
            throw WolinError.invalidWebIDProfile("Invalid Turtle object token")
        }
    }

    private mutating func parseBlankNodePropertyList() throws -> (RDFTerm, Bool) {
        try expectToken(.lBracket, context: "blank node '['")
        let bnode = nextBlankNode()
        if cursor < tokens.count && tokens[cursor] == .rBracket {
            cursor += 1
            return (bnode, false)
        }
        try parsePredicateObjectList(subject: bnode)
        try expectToken(.rBracket, context: "blank node ']'")
        return (bnode, true)
    }

    private mutating func parseCollection() throws -> RDFTerm {
        try expectToken(.lParen, context: "collection '('")
        var items: [RDFTerm] = []
        while cursor < tokens.count && tokens[cursor] != .rParen {
            items.append(try parseObject())
        }
        try expectToken(.rParen, context: "collection ')'")

        guard !items.isEmpty else {
            return .iri(SolidVocabulary.rdfNil)
        }

        let head = nextBlankNode()
        var current = head
        for (idx, item) in items.enumerated() {
            triples.append(RDFTriple(subject: current, predicate: SolidVocabulary.rdfFirst, object: item))
            if idx + 1 < items.count {
                let next = nextBlankNode()
                triples.append(RDFTriple(subject: current, predicate: SolidVocabulary.rdfRest, object: next))
                current = next
            } else {
                triples.append(RDFTriple(subject: current, predicate: SolidVocabulary.rdfRest, object: .iri(SolidVocabulary.rdfNil)))
            }
        }
        return head
    }

    private mutating func parseIRI() throws -> String {
        guard cursor < tokens.count else {
            throw WolinError.invalidWebIDProfile("Unexpected end of Turtle input while expecting IRI")
        }
        switch tokens[cursor] {
        case .iriRef(let raw):
            cursor += 1
            return try WebIdParser.resolveIRI(raw, base: baseIRI)
        case .prefixedName(let prefix, let local):
            cursor += 1
            guard let namespace = prefixes[prefix] else {
                throw WolinError.invalidWebIDProfile("Undefined Turtle prefix '\(prefix):'")
            }
            return namespace + local
        default:
            throw WolinError.invalidWebIDProfile("Expected IRI or prefixed name in Turtle")
        }
    }

    private mutating func nextBlankNode() -> RDFTerm {
        blankCounter += 1
        return .blankNode("b\(blankCounter)")
    }

    private mutating func expectToken(_ expected: TurtleToken, context: String) throws {
        guard cursor < tokens.count, tokens[cursor] == expected else {
            throw WolinError.invalidWebIDProfile("Missing expected '\(expected)' in \(context)")
        }
        cursor += 1
    }
}
