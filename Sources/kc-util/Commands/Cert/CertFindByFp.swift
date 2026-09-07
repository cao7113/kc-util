import ArgumentParser
import Foundation
import KeychainKit

struct CertFindByFp: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "find-by-fp",
        abstract: "根据 SHA-1 或 SHA-256 指纹在 Keychain 中查找证书 (支持从命令行参数或管道接收输入)",
        aliases: ["by-fp", "fp"],
    )

    @Argument(help: "证书的 SHA-1 或 SHA-256 指纹 (Hex 格式)。若未提供，将尝试从标准输入(管道)读取")
    var fingerprint: String?

    func run() throws {
        // 尝试从参数或 STDIN 管道获取并格式化指纹
        guard let targetFP = try resolveFingerprint(), !targetFP.isEmpty else {
            print("错误: 未指定指纹参数，且未通过管道接收到有效的指纹输入。")
            throw ExitCode.failure
        }

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
                " \("SHA-256 指纹".padRightToWidth(18)): \(cert.fingerprintSHA256)",
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

    /// 统一解析与清洗指纹数据（优先解析命令行参数，无参数时尝试读取 STDIN 管道）
    private func resolveFingerprint() throws -> String? {
        // 1. 优先校验命令行显式传递的参数
        if let rawFP = fingerprint?.trimmingCharacters(in: .whitespacesAndNewlines), !rawFP.isEmpty
        {
            return cleanFingerprint(rawFP)
        }

        // 2. 检查标准输入 (STDIN) 是否通过管道接入（非交互终端，isatty 返回 0）
        if isatty(STDIN_FILENO) == 0 {
            let inputData = FileHandle.standardInput.availableData
            if let inputString = String(data: inputData, encoding: .utf8) {
                // 读取第一行非空内容并清洗格式
                let rawFP =
                    inputString
                    .components(separatedBy: .newlines)
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .first(where: { !$0.isEmpty })

                if let rawFP = rawFP {
                    return cleanFingerprint(rawFP)
                }
            }
        }

        return nil
    }

    /// 清理指纹字符串中的冒号、空格并转换为小写
    private func cleanFingerprint(_ raw: String) -> String {
        return
            raw
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: " ", with: "")
            .lowercased()
    }
}
