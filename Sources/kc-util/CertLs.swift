import Foundation
import ArgumentParser

struct CertLs: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ls",
        abstract: "列出 Keychain 中的证书列表 (过滤 Subject 或 Issuer，支持 limit 限制)"
    )

    @Argument(help: "查询关键词 (模糊匹配 Subject 或 Issuer，默认为空匹配所有)")
    var query: String?

    @Option(name: [.short, .customLong("limit")], help: "限制最大输出条数")
    var limit: Int?

    func run() throws {
        let results = try KeychainService.listCertificates(query: query, limit: limit)

        if results.isEmpty {
            if let query = query, !query.isEmpty {
                print("未找到 Subject 或 Issuer 匹配 [\(query)] 的证书。")
            } else {
                print("Keychain 中未找到任何证书。")
            }
            return
        }

        print("==================================================================================================================")
        print(" #  | \("Label (Subject)".padRightToWidth(32)) | \("Issuer".padRightToWidth(32)) | SHA-1 Fingerprint")
        print("------------------------------------------------------------------------------------------------------------------")
        
        for (index, item) in results.enumerated() {
            let seq = String(index + 1).padRightToWidth(3)
            let labelTrunc = item.label.count > 30 ? String(item.label.prefix(27)) + "..." : item.label
            let issuerTrunc = item.issuer.count > 30 ? String(item.issuer.prefix(27)) + "..." : item.issuer
            
            print(" \(seq) | \(labelTrunc.padRightToWidth(32)) | \(issuerTrunc.padRightToWidth(32)) | \(item.fingerprintSHA1)")
        }
        
        print("==================================================================================================================")
        print("共找到 \(results.count) 条证书记录。")
    }
}