import ArgumentParser
import KeychainKit

struct CertLs: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ls",
        abstract: "列出 Keychain 中的证书列表 (过滤 Subject 或 Issuer，支持 limit 限制)",
        aliases: ["list", "l"]
    )

    @Argument(help: "查询关键词 (模糊匹配 Subject 或 Issuer，默认为空匹配所有)")
    var query: String?

    @Option(name: [.short, .customLong("limit")], help: "限制最大输出条数")
    var limit: Int?

    func run() throws {
        let results = try KeychainService.listCertificates(query: query, limit: limit)
        if results.isEmpty {
            if let query, !query.isEmpty {
                print("未找到 Subject 或 Issuer 匹配 [\(query)] 的证书。")
            } else {
                print("Keychain 中未找到任何证书。")
            }
            return
        }

        let labelWidth = max(
            "Subject Label".displayWidth,
            results.map { $0.label.displayWidth }.max() ?? 0
        )
        let header = " #  | \("Subject Label".padRightToWidth(labelWidth)) | SHA-1 Fingerprint"
        let rows = results.enumerated().map { index, item in
            let sequence = String(index + 1).padRightToWidth(3)
            return
                " \(sequence) | \(item.label.padRightToWidth(labelWidth)) | \(item.fingerprintSHA1)"
        }
        let tableWidth = max(header.displayWidth, rows.map { $0.displayWidth }.max() ?? 0)

        print(TableFormatter.line(character: "=", width: tableWidth))
        print(header)
        print(TableFormatter.line(character: "-", width: tableWidth))
        for row in rows {
            print(row)
        }
        print(TableFormatter.line(character: "=", width: tableWidth))
        print("共找到 \(results.count) 条证书记录。")
    }
}
