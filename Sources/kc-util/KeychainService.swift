import Foundation
import Security
import CommonCrypto

enum KeychainError: Error, LocalizedError, Equatable {
    case invalidFingerprintLength
    case notFound
    case unhandledError(status: OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidFingerprintLength:
            return "指纹长度无效 (SHA-1 应为 40 位 Hex，SHA-256 应为 64 位 Hex)。"
        case .notFound:
            return "未找到匹配指纹的证书。"
        case .unhandledError(let status):
            return "Keychain 查询失败，状态码: \(status)"
        }
    }
}

/// 证书详细属性结构体
struct CertificateDetail: Sendable {
    let subject: String
    let issuer: String
    let serialNumber: String
    let notBefore: Date?
    let notAfter: Date?
    let fingerprintSHA1: String
    let fingerprintSHA256: String
}

struct CertificateSummary: Sendable {
    let label: String          // 即 Subject Summary
    let issuer: String         // 发行者信息
    let fingerprintSHA1: String
}

struct KeychainService {
/// 获取证书的 Issuer Summary
    private static func copyIssuerSummary(_ cert: SecCertificate) -> String {
        // 传入 nil 获取证书的所有属性值
        if let valuesDict = SecCertificateCopyValues(cert, nil, nil) as? [String: [String: Any]] {
            for (_, item) in valuesDict {
                if let label = item[kSecPropertyKeyLabel as String] as? String, label.contains("Issuer") {
                    if let valueList = item[kSecPropertyKeyValue as String] as? [[String: Any]] {
                        let components = extractStringValues(from: valueList)
                        if !components.isEmpty {
                            return components.joined(separator: ", ")
                        }
                    }
                }
            }
        }
        
        // 如果没有单独找到 Issuer 属性（例如根证书 Root CA），兜底退回到 Subject 描述
        let subject = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown Subject"
        return subject
    }
    // /// 获取证书的 Issuer Summary
    // private static func copyIssuerSummary(_ cert: SecCertificate) -> String {
    //     // 通过 SecCertificateCopyValues 提取 Issuer 属性
    //     let keys = [kSecOIDIssuer: [kSecPropertyKeyLabel: "Issuer"]] as CFDictionary
    //     if let values = SecCertificateCopyValues(cert, [kSecOIDIssuer] as CFArray, nil) as? [CFString: Any],
    //        let issuerDict = values[kSecOIDIssuer] as? [String: Any],
    //        let valueList = issuerDict[kSecPropertyKeyValue as String] as? [[String: Any]] {
            
    //         // 组装 Common Name (CN) 或完整的 Issuer 描述
    //         let issuerParts = valueList.compactMap { dict -> String? in
    //             guard let val = dict[kSecPropertyKeyValue as String] as? String else { return nil }
    //             return val
    //         }
    //         if !issuerParts.isEmpty {
    //             return issuerParts.joined(separator: ", ")
    //         }
    //     }
        
    //     // 兜底方案：无法简单解析时返回默认提示
    //     return "Unknown Issuer"
    // }

    /// 列出 Keychain 中的证书，支持模糊匹配 Subject 或 Issuer，并支持数量限制
    static func listCertificates(query filterQuery: String? = nil, limit: Int? = nil) throws -> [CertificateSummary] {
        let queryDict: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(queryDict as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return []
            }
            throw KeychainError.unhandledError(status: status)
        }

        guard let certs = result as? [SecCertificate] else {
            return []
        }

        var summaries: [CertificateSummary] = []
        let cleanQuery = filterQuery?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""

        for cert in certs {
            if let maxLimit = limit, summaries.count >= maxLimit {
                break
            }

            let subject = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown Subject"
            let issuer = copyIssuerSummary(cert)
            let certData = SecCertificateCopyData(cert) as Data
            let fpSHA1 = sha1(data: certData)

            // query 只匹配 Subject (label) 或 Issuer
            if cleanQuery.isEmpty || subject.lowercased().contains(cleanQuery) || issuer.lowercased().contains(cleanQuery) {
                summaries.append(CertificateSummary(
                    label: subject,
                    issuer: issuer,
                    fingerprintSHA1: fpSHA1
                ))
            }
        }

        return summaries
    }
    
    static func findCertificates(fingerprint targetFP: String) throws -> [CertificateDetail] {
        let cleanFP = targetFP.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        
        guard cleanFP.count == 40 || cleanFP.count == 64 else {
            throw KeychainError.invalidFingerprintLength
        }

        let query: [String: Any] = [
            // 由于没有显式指定 kSecMatchSearchList 参数，系统会直接采用 macOS 的默认 Keychain Search List
            // kSecMatchSearchList as String: keychainList // 自定义 Keychain 数组
            kSecClass as String: kSecClassCertificate,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw KeychainError.notFound
            }
            throw KeychainError.unhandledError(status: status)
        }

        guard let certs = result as? [SecCertificate] else {
            throw KeychainError.notFound
        }

        var matchedCertificates: [CertificateDetail] = []

        for cert in certs {
            let certData = SecCertificateCopyData(cert) as Data
            let computedFP = cleanFP.count == 40 ? sha1(data: certData) : sha256(data: certData)

            if computedFP == cleanFP {
                let detail = parseCertificateDetail(cert: cert, certData: certData)
                matchedCertificates.append(detail)
            }
        }

        if matchedCertificates.isEmpty {
            throw KeychainError.notFound
        }

        return matchedCertificates
    }

    // MARK: - Certificate Detail Parser

    private static func parseCertificateDetail(cert: SecCertificate, certData: Data) -> CertificateDetail {
        let subject = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown Subject"
        
        // 1. 序列号解析
        var serialNumberStr = "Unknown"
        if let serialData = SecCertificateCopySerialNumberData(cert, nil) as Data? {
            serialNumberStr = serialData.map { String(format: "%02X", $0) }.joined(separator: ":")
        }

        var issuerStr = "Unknown Issuer"
        var notBefore: Date?
        var notAfter: Date?

        // 2. 深度递归解析 SecCertificateCopyValues 字典
        if let valuesDict = SecCertificateCopyValues(cert, nil, nil) as? [String: [String: Any]] {
            
            // 提取 Issuer
            for (_, item) in valuesDict {
                if let label = item[kSecPropertyKeyLabel as String] as? String, label.contains("Issuer") {
                    if let valueList = item[kSecPropertyKeyValue as String] as? [[String: Any]] {
                        let components = extractStringValues(from: valueList)
                        if !components.isEmpty {
                            issuerStr = components.joined(separator: ", ")
                        }
                    }
                }
            }

            // 递归提取所有 Date 属性 (Not Before / Not After)
            let dates = extractDates(from: valuesDict)
            notBefore = dates.notBefore
            notAfter = dates.notAfter
        }

        // 如果 Issuer 未解析成功，作为 Root 证书情况兜底处理
        if issuerStr == "Unknown Issuer" {
            issuerStr = subject
        }

        return CertificateDetail(
            subject: subject,
            issuer: issuerStr,
            serialNumber: serialNumberStr,
            notBefore: notBefore,
            notAfter: notAfter,
            fingerprintSHA1: sha1(data: certData),
            fingerprintSHA256: sha256(data: certData)
        )
    }

    // MARK: - Helper Parsing Methods

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
                        let res = extractDates(from: entry)
                        if res.notBefore != nil { notBefore = res.notBefore }
                        if res.notAfter != nil { notAfter = res.notAfter }
                    }
                }
            }
        }
        return (notBefore, notAfter)
    }

    // MARK: - Crypto Helpers

    private static func sha1(data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func sha256(data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}