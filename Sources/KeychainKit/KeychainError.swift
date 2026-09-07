import Foundation
import Security

public enum KeychainError: Error, LocalizedError, Equatable {
    case invalidFingerprintLength
    case notFound
    case unhandledError(status: OSStatus)

    public var errorDescription: String? {
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