import ArgumentParser

struct RootCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "kc-util",
        abstract: "弥补 security 命令行工具不足的 macOS Keychain 增强工具",
        version: AppVersion.current,
        subcommands: [Cert.self]
    )
}