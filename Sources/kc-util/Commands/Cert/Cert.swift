import ArgumentParser

struct Cert: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "证书相关操作",
        subcommands: [CertFindByFp.self, CertLs.self]
    )
}