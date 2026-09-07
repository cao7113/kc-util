// The Swift Programming Language
// https://docs.swift.org/swift-book

// @main
// struct kc_util {
//     static func main() {
//         print("Hello, world!")
//     }
// }

import Foundation
import ArgumentParser

@main
struct KcUtil: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "kc-util",
        abstract: "弥补 security 命令行工具不足的 macOS Keychain 增强工具",
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
        let cleanFP = fingerprint
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: " ", with: "")
            .lowercased()

        print("正在检索指纹为 [\(cleanFP)] 的证书...")
        
        try KeychainService.findCertificate(fingerprint: cleanFP)
    }
}