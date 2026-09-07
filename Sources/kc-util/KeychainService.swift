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

struct KeychainService {
    
    static func findCertificates(fingerprint targetFP: String) throws -> [CertificateDetail] {
        let cleanFP = targetFP.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        
        guard cleanFP.count == 40 || cleanFP.count == 64 else {
            throw KeychainError.invalidFingerprintLength
        }

        let query: [String: Any] = [
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