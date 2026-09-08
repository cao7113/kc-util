import Foundation
import Security
import CommonCrypto

public struct KeychainService {
    private static func copyIssuerSummary(_ cert: SecCertificate) -> String {
        if let valuesDict = SecCertificateCopyValues(cert, nil, nil) as? [AnyHashable: Any] {
            for (_, rawItem) in valuesDict {
                guard let item = rawItem as? [AnyHashable: Any] else { continue }
                if let label = item[kSecPropertyKeyLabel as String] as? String, label.contains("Issuer"),
                   let valueList = item[kSecPropertyKeyValue as String] as? [[AnyHashable: Any]] {
                    let components = extractStringValues(from: valueList)
                    if !components.isEmpty { return components.joined(separator: ", ") }
                }
            }
        }
        return (SecCertificateCopySubjectSummary(cert) as String?) ?? "Unknown Subject"
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
            let subject = (SecCertificateCopySubjectSummary(cert) as String?) ?? "Unknown Subject"
            let issuer = copyIssuerSummary(cert)
            guard let certData = SecCertificateCopyData(cert) as Data? else { continue }
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
            guard let certData = SecCertificateCopyData(cert) as Data? else { continue }
            let computedFP = cleanFP.count == 40 ? sha1(data: certData) : sha256(data: certData)
            if computedFP == cleanFP { 
                matchedCertificates.append(parseCertificateDetail(cert: cert, certData: certData)) 
            }
        }
        guard !matchedCertificates.isEmpty else { throw KeychainError.notFound }
        return matchedCertificates
    }

    private static func parseCertificateDetail(cert: SecCertificate, certData: Data) -> CertificateDetail {
        let subject = (SecCertificateCopySubjectSummary(cert) as String?) ?? "Unknown Subject"
        var serialNumberStr = "Unknown"
        if let serialData = SecCertificateCopySerialNumberData(cert, nil) as Data? {
            serialNumberStr = serialData.map { String(format: "%02X", $0) }.joined(separator: ":")
        }

        var issuerStr = "Unknown Issuer"
        var notBefore: Date?
        var notAfter: Date?

        // 使用 [AnyHashable: Any] 进行安全的弱类型解析，防止类型强转换触发 SIGTRAP
        if let valuesDict = SecCertificateCopyValues(cert, nil, nil) as? [AnyHashable: Any] {
            for (_, rawItem) in valuesDict {
                guard let item = rawItem as? [AnyHashable: Any] else { continue }
                if let label = item[kSecPropertyKeyLabel as String] as? String, label.contains("Issuer"),
                   let valueList = item[kSecPropertyKeyValue as String] as? [[AnyHashable: Any]] {
                    let components = extractStringValues(from: valueList)
                    if !components.isEmpty { issuerStr = components.joined(separator: ", ") }
                }
            }
            let dates = extractDates(from: valuesDict)
            notBefore = dates.notBefore
            notAfter = dates.notAfter
        }
        if issuerStr == "Unknown Issuer" { issuerStr = subject }

        return CertificateDetail(
            subject: subject,
            issuer: issuerStr,
            serialNumber: serialNumberStr,
            notBefore: notBefore,
            notAfter: notAfter,
            fingerprintSHA1: sha1(data: certData),
            fingerprintSHA256: sha256(data: certData),
            keychainPath: keychainPath(for: cert)
        )
    }

    private static func keychainPath(for cert: SecCertificate) -> String {
        // SecKeychain / SecKeychainGetPath are deprecated, and their use emits compiler warnings.
        // The keychain path is only for display, so we intentionally avoid deprecated APIs and
        // fall back to a stable, non-warning value instead of relying on legacy Security calls.
        _ = cert
        return "Unknown Keychain"
    }

    private static func extractStringValues(from list: [[AnyHashable: Any]]) -> [String] {
        var results: [String] = []
        for dict in list {
            if let value = dict[kSecPropertyKeyValue as String] as? String {
                results.append(value)
            } else if let nested = dict[kSecPropertyKeyValue as String] as? [[AnyHashable: Any]] {
                results.append(contentsOf: extractStringValues(from: nested))
            }
        }
        return results
    }

    private static func extractDates(from dict: [AnyHashable: Any]) -> (notBefore: Date?, notAfter: Date?) {
        var notBefore: Date?
        var notAfter: Date?

        for (_, rawValue) in dict {
            // 确保当前节点能够安全转换为字典，若不是字典则忽略
            guard let subDict = rawValue as? [AnyHashable: Any] else { continue }

            if let label = subDict[kSecPropertyKeyLabel as String] as? String {
                // 安全判定 CFAbsoluteTime 或 NSDate
                let absoluteTime: CFAbsoluteTime? = {
                    if let time = subDict[kSecPropertyKeyValue as String] as? CFAbsoluteTime {
                        return time
                    } else if let nsNumber = subDict[kSecPropertyKeyValue as String] as? NSNumber {
                        return nsNumber.doubleValue
                    }
                    return nil
                }()

                if let absoluteTime = absoluteTime {
                    let date = Date(timeIntervalSinceReferenceDate: absoluteTime)
                    let lowerLabel = label.lowercased()
                    if lowerLabel.contains("not valid before") || lowerLabel.contains("before") || label.contains("开始") {
                        notBefore = date
                    } else if lowerLabel.contains("not valid after") || lowerLabel.contains("after") || label.contains("过期") {
                        notAfter = date
                    }
                }
            }

            // 安全判断 `kSecPropertyKeyValue` 是否为嵌套列表，避免对非 Array 节点强转崩溃
            if let nestedList = subDict[kSecPropertyKeyValue as String] as? [[AnyHashable: Any]] {
                for entry in nestedList {
                    let dates = extractDates(from: entry)
                    if dates.notBefore != nil { notBefore = dates.notBefore }
                    if dates.notAfter != nil { notAfter = dates.notAfter }
                }
            }
        }
        return (notBefore, notAfter)
    }

    private static func sha1(data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            if let baseAddress = buffer.baseAddress {
                _ = CC_SHA1(baseAddress, CC_LONG(data.count), &digest)
            }
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func sha256(data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes { buffer in
            if let baseAddress = buffer.baseAddress {
                _ = CC_SHA256(baseAddress, CC_LONG(data.count), &digest)
            }
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}