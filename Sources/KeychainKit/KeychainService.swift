import Foundation
import Security
import CommonCrypto

public struct KeychainService {
    private static func copyIssuerSummary(_ cert: SecCertificate) -> String {
        if let valuesDict = SecCertificateCopyValues(cert, nil, nil) as? [String: [String: Any]] {
            for (_, item) in valuesDict {
                if let label = item[kSecPropertyKeyLabel as String] as? String, label.contains("Issuer"),
                   let valueList = item[kSecPropertyKeyValue as String] as? [[String: Any]] {
                    let components = extractStringValues(from: valueList)
                    if !components.isEmpty { return components.joined(separator: ", ") }
                }
            }
        }
        return SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown Subject"
    }

    public static func listCertificates(query filterQuery: String? = nil, limit: Int? = nil) throws -> [CertificateSummary] {
        let queryDict: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(queryDict as CFDictionary, &result)
        guard status == errSecSuccess else {
            if status == errSecItemNotFound { return [] }
            throw KeychainError.unhandledError(status: status)
        }
        guard let certs = result as? [SecCertificate] else { return [] }

        var summaries: [CertificateSummary] = []
        let cleanQuery = filterQuery?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        for cert in certs {
            if let maxLimit = limit, summaries.count >= maxLimit { break }
            let subject = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown Subject"
            let issuer = copyIssuerSummary(cert)
            let certData = SecCertificateCopyData(cert) as Data
            let fpSHA1 = sha1(data: certData)
            if cleanQuery.isEmpty || subject.lowercased().contains(cleanQuery) || issuer.lowercased().contains(cleanQuery) {
                summaries.append(CertificateSummary(label: subject, issuer: issuer, fingerprintSHA1: fpSHA1))
            }
        }
        return summaries
    }

    public static func findCertificates(fingerprint targetFP: String) throws -> [CertificateDetail] {
        let cleanFP = targetFP.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanFP.count == 40 || cleanFP.count == 64 else { throw KeychainError.invalidFingerprintLength }

        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            if status == errSecItemNotFound { throw KeychainError.notFound }
            throw KeychainError.unhandledError(status: status)
        }
        guard let certs = result as? [SecCertificate] else { throw KeychainError.notFound }

        var matchedCertificates: [CertificateDetail] = []
        for cert in certs {
            let certData = SecCertificateCopyData(cert) as Data
            let computedFP = cleanFP.count == 40 ? sha1(data: certData) : sha256(data: certData)
            if computedFP == cleanFP { matchedCertificates.append(parseCertificateDetail(cert: cert, certData: certData)) }
        }
        guard !matchedCertificates.isEmpty else { throw KeychainError.notFound }
        return matchedCertificates
    }

    private static func parseCertificateDetail(cert: SecCertificate, certData: Data) -> CertificateDetail {
        let subject = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown Subject"
        var serialNumberStr = "Unknown"
        if let serialData = SecCertificateCopySerialNumberData(cert, nil) as Data? {
            serialNumberStr = serialData.map { String(format: "%02X", $0) }.joined(separator: ":")
        }

        var issuerStr = "Unknown Issuer"
        var notBefore: Date?
        var notAfter: Date?
        if let valuesDict = SecCertificateCopyValues(cert, nil, nil) as? [String: [String: Any]] {
            for (_, item) in valuesDict {
                if let label = item[kSecPropertyKeyLabel as String] as? String, label.contains("Issuer"),
                   let valueList = item[kSecPropertyKeyValue as String] as? [[String: Any]] {
                    let components = extractStringValues(from: valueList)
                    if !components.isEmpty { issuerStr = components.joined(separator: ", ") }
                }
            }
            let dates = extractDates(from: valuesDict)
            notBefore = dates.notBefore
            notAfter = dates.notAfter
        }
        if issuerStr == "Unknown Issuer" { issuerStr = subject }
        return CertificateDetail(subject: subject, issuer: issuerStr, serialNumber: serialNumberStr, notBefore: notBefore, notAfter: notAfter, fingerprintSHA1: sha1(data: certData), fingerprintSHA256: sha256(data: certData), keychainPath: keychainPath(for: cert))
    }

    private static func keychainPath(for cert: SecCertificate) -> String {
        var keychain: SecKeychain?
        guard SecKeychainItemCopyKeychain(cert as! SecKeychainItem, &keychain) == errSecSuccess, let keychain else {
            return "Unknown Keychain"
        }

        var path = [Int8](repeating: 0, count: 4096)
        var pathLength = UInt32(path.count)
        guard SecKeychainGetPath(keychain, &pathLength, &path) == errSecSuccess else {
            return "Unknown Keychain"
        }

        return String(decoding: path.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    private static func extractStringValues(from list: [[String: Any]]) -> [String] {
        var results: [String] = []
        for dict in list {
            if let value = dict[kSecPropertyKeyValue as String] as? String {
                results.append(value)
            } else if let nested = dict[kSecPropertyKeyValue as String] as? [[String: Any]] {
                results.append(contentsOf: extractStringValues(from: nested))
            }
        }
        return results
    }

    private static func extractDates(from dict: [String: Any]) -> (notBefore: Date?, notAfter: Date?) {
        var notBefore: Date?
        var notAfter: Date?
        for (_, value) in dict {
            if let subDict = value as? [String: Any] {
                if let label = subDict[kSecPropertyKeyLabel as String] as? String,
                   let absoluteTime = subDict[kSecPropertyKeyValue as String] as? CFAbsoluteTime {
                    let date = Date(timeIntervalSinceReferenceDate: absoluteTime)
                    let lowerLabel = label.lowercased()
                    if lowerLabel.contains("not valid before") || lowerLabel.contains("before") || label.contains("开始") {
                        notBefore = date
                    } else if lowerLabel.contains("not valid after") || lowerLabel.contains("after") || label.contains("过期") {
                        notAfter = date
                    }
                }
                if let nestedList = subDict[kSecPropertyKeyValue as String] as? [[String: Any]] {
                    for entry in nestedList {
                        let dates = extractDates(from: entry)
                        if dates.notBefore != nil { notBefore = dates.notBefore }
                        if dates.notAfter != nil { notAfter = dates.notAfter }
                    }
                }
            }
        }
        return (notBefore, notAfter)
    }

    private static func sha1(data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest) }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func sha256(data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &digest) }
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}