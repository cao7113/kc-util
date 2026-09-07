import ArgumentParser
import Foundation
import KeychainKit

struct CertFindByFp: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "find-by-fp",
        abstract: "根据 SHA-1 或 SHA-256 指纹在 Keychain 中查找证书"
    )

    @Argument(help: "证书的 SHA-1 或 SHA-256 指纹 (Hex 格式)")
    var fingerprint: String

    func run() throws {
        let targetFP = fingerprint
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: " ", with: "")
            .lowercased()

        print("正在检索指纹为 [\(targetFP)] 的证书...")
        let certs = try KeychainService.findCertificates(fingerprint: targetFP)
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss ZZZ"

        for (index, cert) in certs.enumerated() {
            let details = [
                " \("主题 (Subject)".padRightToWidth(18)): \(cert.subject)",
                " \("签发者 (Issuer)".padRightToWidth(18)): \(cert.issuer)",
                " \("序列号 (Serial)".padRightToWidth(18)): \(cert.serialNumber)",
                " \("生效时间 (Before)".padRightToWidth(18)): \(cert.notBefore.map { formatter.string(from: $0) } ?? "Unknown")",
                " \("失效时间 (After)".padRightToWidth(18)): \(cert.notAfter.map { formatter.string(from: $0) } ?? "Unknown")",
                " \("所在 Keychain".padRightToWidth(18)): \(cert.keychainPath)",
                " \("SHA-1 指纹".padRightToWidth(18)): \(cert.fingerprintSHA1)",
                " \("SHA-256 指纹".padRightToWidth(18)): \(cert.fingerprintSHA256)"
            ]
            let title = " 匹配结果 #\(index + 1)"
            let contentWidth = max(title.displayWidth, details.map { $0.displayWidth }.max() ?? 0)

            print(TableFormatter.line(character: "=", width: contentWidth))
            print(title)
            print(TableFormatter.line(character: "-", width: contentWidth))
            for detail in details {
                print(detail)
            }
            print(TableFormatter.line(character: "=", width: contentWidth))
        }
    }
}