// The Swift Programming Language
// https://docs.swift.org/swift-book

import ArgumentParser
import Foundation

extension String {
    /// 计算字符串在终端显示时的实际列宽（全角字符计 2 宽度，半角计 1）
    var displayWidth: Int {
        return self.reduce(0) { count, char in
            return count + (char.isASCII ? 1 : 2)
        }
    }

    /// 将包含中文字符的字符串填充至指定的终端 displayWidth
    func padRightToWidth(_ width: Int) -> String {
        let currentWidth = self.displayWidth
        if currentWidth >= width { return self }
        return self + String(repeating: " ", count: width - currentWidth)
    }
}

@main
struct KcUtil: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "kc-util",
        abstract: "弥补 security 命令行工具不足的 macOS Keychain 增强工具",
        // 动态使用插件生成的版本号
        version: AppVersion.current,
        subcommands: [Cert.self]
    )
}

// 定义 cert 子命令组
struct Cert: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "证书相关操作",
        subcommands: [FindByFP.self]
    )
}

// 定义 cert find-by-fp 具体命令
struct FindByFP: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "find-by-fp",
        abstract: "根据 SHA-1 或 SHA-256 指纹在 Keychain 中查找证书"
    )

    @Argument(help: "证书的 SHA-1 或 SHA-256 指纹 (Hex 格式)")
    var fingerprint: String

    func run() throws {
        // 清理输入的指纹格式（移除冒号、空格并转小写）
        let targetFP =
            fingerprint
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: " ", with: "")
            .lowercased()

        print("正在检索指纹为 [\(targetFP)] 的证书...")

        // try KeychainService.findCertificate(fingerprint: cleanFP)

        let certs = try KeychainService.findCertificates(fingerprint: targetFP)

        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss ZZZ"

        for (index, cert) in certs.enumerated() {
            print("==================================================================")
            print(" 匹配结果 #\(index + 1)")
            print("------------------------------------------------------------------")
            print(" \("主题 (Subject)".padRightToWidth(18)): \(cert.subject)")
            print(" \("签发者 (Issuer)".padRightToWidth(18)): \(cert.issuer)")
            print(" \("序列号 (Serial)".padRightToWidth(18)): \(cert.serialNumber)")
            print(
                " \("生效时间 (Before)".padRightToWidth(18)): \(cert.notBefore.map { formatter.string(from: $0) } ?? "Unknown")"
            )
            print(
                " \("失效时间 (After)".padRightToWidth(18)): \(cert.notAfter.map { formatter.string(from: $0) } ?? "Unknown")"
            )
            print(" \("SHA-1 指纹".padRightToWidth(18)): \(cert.fingerprintSHA1)")
            print(" \("SHA-256 指纹".padRightToWidth(18)): \(cert.fingerprintSHA256)")
            print("==================================================================")
        }
    }
}
