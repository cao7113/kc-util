import Testing
@testable import kc_util

struct ArgumentParsingTests {
    @Test("根命令包含 cert 子命令")
    func rootCommandHasCertSubcommand() {
        #expect(RootCommand.configuration.subcommands.count == 1)
        #expect(RootCommand.configuration.subcommands.first is Cert.Type)
    }
}