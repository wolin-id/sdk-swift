// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 Entropy Paradox, Inc. (https://wolin.id)

import Foundation
@preconcurrency import CryptoKit

/// RFC 4648 Section 5 unpadded Base64URL and SHA-256 helpers.
public enum Base64URL: Sendable {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ encoded: String) throws -> Data {
        guard !encoded.isEmpty,
              !encoded.contains("="),
              !encoded.contains("+"),
              !encoded.contains("/") else {
            throw WolinError.cryptographyError("Invalid unpadded Base64URL string")
        }
        var standard = encoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let rem = standard.count % 4
        if rem == 1 {
            throw WolinError.cryptographyError("Malformed Base64URL segment length")
        } else if rem > 1 {
            standard.append(String(repeating: "=", count: 4 - rem))
        }
        guard let decoded = Data(base64Encoded: standard) else {
            throw WolinError.cryptographyError("Malformed Base64URL characters")
        }
        return decoded
    }

    public static func sha256(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return encode(Data(digest))
    }
}

/// Public NIST P-256 (`ES256`) JSON Web Key (RFC 7517 / RFC 7638).
/// Never contains private scalar material (`d`).
public struct PublicJWK: Sendable, Equatable, Codable {
    public let crv: String
    public let kty: String
    public let x: String
    public let y: String

    public init(crv: String = "P-256", kty: String = "EC", x: String, y: String) {
        self.crv = crv
        self.kty = kty
        self.x = x
        self.y = y
    }

    /// RFC 7638 Section 3.1 canonical JSON with lexicographically ordered required EC members (`crv`, `kty`, `x`, `y`).
    public var canonicalJSON: String {
        "{\"crv\":\(Self.jsonString(crv)),\"kty\":\(Self.jsonString(kty)),\"x\":\(Self.jsonString(x)),\"y\":\(Self.jsonString(y))}"
    }

    /// Computes the RFC 7638 SHA-256 JWK Thumbprint (`jkt`) as unpadded Base64URL.
    public func thumbprintSHA256() -> String {
        Base64URL.sha256(Data(canonicalJSON.utf8))
    }

    private static func jsonString(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"":
                out.append("\\\"")
            case "\\":
                out.append("\\\\")
            case "\n":
                out.append("\\n")
            case "\r":
                out.append("\\r")
            case "\t":
                out.append("\\t")
            default:
                if scalar.value < 0x20 {
                    out.append(String(format: "\\u%04x", scalar.value))
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out.append("\"")
        return out
    }
}

/// JOSE Header for an RFC 9449 DPoP Proof JWT (`typ: "dpop+jwt"`, `alg: "ES256"`).
public struct DPoPHeader: Sendable, Equatable, Codable {
    public let typ: String
    public let alg: String
    public let jwk: PublicJWK

    public init(typ: String = "dpop+jwt", alg: String = "ES256", jwk: PublicJWK) {
        self.typ = typ
        self.alg = alg
        self.jwk = jwk
    }
}

/// JWT Payload claims for an RFC 9449 DPoP Proof JWT.
public struct DPoPProofClaims: Sendable, Equatable, Codable {
    public let jti: String
    public let htm: String
    public let htu: String
    public let iat: Int64
    public let ath: String?
    public let nonce: String?

    public init(
        jti: String,
        htm: String,
        htu: String,
        iat: Int64,
        ath: String? = nil,
        nonce: String? = nil
    ) {
        self.jti = jti
        self.htm = htm
        self.htu = htu
        self.iat = iat
        self.ath = ath
        self.nonce = nonce
    }
}

/// Concurrency-safe RFC 9449 DPoP Proof JWT signer backed by Apple CryptoKit (`P256.Signing.PrivateKey` / `ES256`).
public struct DPoPSigner: Sendable {
    private static let maxJTILength = 256
    private static let maxHTULength = 2048

    private let rawPrivateKey: Data
    public let publicJWK: PublicJWK
    public let jwkThumbprint: String

    /// Creates a new `DPoPSigner` from a CryptoKit `P256.Signing.PrivateKey` (generates an ephemeral P-256 keypair by default).
    public init(privateKey: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) { // gitleaks:allow
        self.rawPrivateKey = privateKey.rawRepresentation

        // ANSI X9.63 uncompressed public key representation: 0x04 (1 byte) || X (32 bytes) || Y (32 bytes)
        let x963 = privateKey.publicKey.x963Representation
        let xCoord = Data(x963.dropFirst(1).prefix(32))
        let yCoord = Data(x963.dropFirst(33).prefix(32))

        let jwk = PublicJWK(
            crv: "P-256",
            kty: "EC",
            x: Base64URL.encode(xCoord),
            y: Base64URL.encode(yCoord)
        )
        self.publicJWK = jwk
        self.jwkThumbprint = jwk.thumbprintSHA256()
    }

    /// Creates a `DPoPSigner` from a 32-byte raw P-256 private scalar representation.
    public init(rawRepresentation: Data) throws {
        do {
            let key = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation)
            self.init(privateKey: key)
        } catch {
            throw WolinError.cryptographyError("Invalid P-256 raw private key: \(error.localizedDescription)")
        }
    }

    /// Creates a `DPoPSigner` from a PEM-encoded P-256 private key.
    public init(pemRepresentation: String) throws {
        do {
            let key = try P256.Signing.PrivateKey(pemRepresentation: pemRepresentation)
            self.init(privateKey: key)
        } catch {
            throw WolinError.cryptographyError("Invalid P-256 PEM private key: \(error.localizedDescription)")
        }
    }

    /// Reconstructs the underlying CryptoKit `P256.Signing.PrivateKey`.
    public var privateKey: P256.Signing.PrivateKey { // gitleaks:allow
        // Safe: validated at initialization time from an authentic 32-byte P256 scalar.
        try! P256.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
    }

    /// Returns the corresponding CryptoKit `P256.Signing.PublicKey`.
    public var publicKey: P256.Signing.PublicKey {
        privateKey.publicKey
    }

    /// Computes RFC 9449 Section 4.2 `ath` (base64url-encoded SHA-256 hash of the ASCII access token).
    public static func computeAccessTokenHash(_ accessToken: String) -> String {
        Base64URL.sha256(Data(accessToken.utf8))
    }

    /// Normalizes a target HTTP(S) `URL` into an RFC 9449 Section 4.2 `htu` string (stripping query and fragment).
    public static func normalizeHTU(_ url: URL) throws -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
            throw WolinError.invalidDPoPTarget("Malformed URL '\(url.absoluteString)'")
        }
        guard components.user == nil, components.password == nil else {
            throw WolinError.invalidDPoPTarget("Userinfo credentials are forbidden in DPoP htu")
        }
        guard let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "https" else {
            throw WolinError.invalidDPoPTarget("DPoP htu requires http or https scheme")
        }
        guard let rawHost = components.percentEncodedHost, !rawHost.isEmpty else {
            throw WolinError.invalidDPoPTarget("DPoP htu is missing host authority")
        }
        let host = rawHost.lowercased()

        let portSuffix: String
        if let port = components.port {
            let isDefaultPort = (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
            portSuffix = isDefaultPort ? "" : ":\(port)"
        } else {
            portSuffix = ""
        }

        let path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        let normalized = "\(scheme)://\(host)\(portSuffix)\(path)"
        guard normalized.utf8.count <= maxHTULength else {
            throw WolinError.invalidDPoPTarget("DPoP htu exceeds maximum URI length")
        }
        return normalized
    }

    /// Signs a compact ES256 RFC 9449 DPoP proof JWT (`header.payload.signature`) for an HTTP request.
    public func signProof(
        httpMethod: String,
        url: URL,
        accessToken: String? = nil,
        nonce: String? = nil,
        jti: String = UUID().uuidString.lowercased(),
        issuedAt: Date = Date()
    ) throws -> String {
        let method = httpMethod.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard !method.isEmpty,
              !method.unicodeScalars.contains(where: { $0.isASCII && ($0.value <= 0x20 || $0.value == 0x7F) }) else {
            throw WolinError.invalidDPoPTarget("HTTP method must be a non-empty token")
        }

        let cleanJTI = jti.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanJTI.isEmpty,
              cleanJTI.utf8.count <= Self.maxJTILength,
              !cleanJTI.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) else {
            throw WolinError.invalidDPoPTarget("DPoP jti must be 1...256 printable characters")
        }

        let htu = try Self.normalizeHTU(url)

        let ath: String?
        if let token = accessToken {
            let trimmedToken = token.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedToken.isEmpty else {
                throw WolinError.invalidDPoPTarget("Access token must not be empty when provided")
            }
            ath = Self.computeAccessTokenHash(trimmedToken)
        } else {
            ath = nil
        }

        let cleanNonce: String?
        if let rawNonce = nonce {
            let trimmed = rawNonce.trimmingCharacters(in: .whitespacesAndNewlines)
            cleanNonce = trimmed.isEmpty ? nil : trimmed
        } else {
            cleanNonce = nil
        }

        let header = DPoPHeader(typ: "dpop+jwt", alg: "ES256", jwk: publicJWK)
        let claims = DPoPProofClaims(
            jti: cleanJTI,
            htm: method,
            htu: htu,
            iat: Int64(issuedAt.timeIntervalSince1970),
            ath: ath,
            nonce: cleanNonce
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]

        let headerData: Data
        let payloadData: Data
        do {
            headerData = try encoder.encode(header)
            payloadData = try encoder.encode(claims)
        } catch {
            throw WolinError.cryptographyError("Failed to encode DPoP JWT JSON: \(error.localizedDescription)")
        }

        let signingInput = "\(Base64URL.encode(headerData)).\(Base64URL.encode(payloadData))"
        let signature: P256.Signing.ECDSASignature
        do {
            let signingKey = try P256.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
            signature = try signingKey.signature(for: Data(signingInput.utf8))
        } catch {
            throw WolinError.cryptographyError("ES256 signature failed: \(error.localizedDescription)")
        }

        // RFC 7518 Section 3.4: ES256 JWS signature is the 64-octet raw concatenation R || S (not ASN.1 DER).
        let signatureB64 = Base64URL.encode(signature.rawRepresentation)
        return "\(signingInput).\(signatureB64)"
    }
}
