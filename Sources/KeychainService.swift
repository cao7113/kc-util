import Foundation
import Security
import CommonCrypto

enum KeychainError: Error, CustomStringErrorConvertible {
    case notFound
    case unhandledError(status: OSStatus)

    var description: String {
        switch self {
        case .notFound:
            return "未找到匹配指纹的证书。"
        case .unhandledError(let status):
            return "Keychain 查询失败，状态码: \(status)"
        }
    }
}

protocol CustomStringErrorConvertible: LocalizedError {
    var description: String { get }
}

extension CustomStringErrorConvertible {
    var errorDescription: String? { return description }
}

struct KeychainService {
    static func findCertificate(fingerprint targetFP: String) throws {
        // 校验指纹长度 (SHA-1 为 40 个字符，SHA-256 为 64 个字符)
        guard targetFP.count == 40 || targetFP.count == 64 else {
            print("错误: 指纹长度无效 (SHA-1 应为 40 位 Hex，SHA-256 应为 64 位 Hex)")
            return
        }

        // 构建 Keychain 查询字典
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

        var matchedCount = 0

        for cert in certs {
            let certData = SecCertificateCopyData(cert) as Data
            
            // 根据目标指纹字符长度判定使用 SHA-1 还是 SHA-256
            let computedFP = targetFP.count == 40 ? sha1(data: certData) : sha256(data: certData)

            if computedFP.lowercased() == targetFP {
                matchedCount += 1
                let summary = SecCertificateCopySubjectSummary(cert) as String? ?? "Unknown Subject"
                print("==========================================")
                print("匹配成功 #\(matchedCount)")
                print("主题 (Subject) : \(summary)")
                print("指纹 (Hex)     : \(computedFP)")
                print("==========================================")
            }
        }

        if matchedCount == 0 {
            print("未在 Keychain 中找到匹配的证书。")
        }
    }

    // SHA-1 计算
    private static func sha1(data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // SHA-256 计算
    private static func sha256(data: Data) -> String {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}