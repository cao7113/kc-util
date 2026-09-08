import PackagePlugin
import Foundation

@main
struct GenerateVersionPlugin: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) async throws -> [Command] {
        let generatedSourceDir = context.pluginWorkDirectoryURL.appending(path: "GeneratedSources")
        let generatedFile = generatedSourceDir.appending(path: "Version.g.swift")
        
        // 尝试通过 git describe 获取最新 Tag，失败时回退到开发版本 0.0.0-dev。
        // 关键修正：静默 git 的 stderr，避免在没有 tag / 浅克隆仓库时污染 swift test 输出。
        let gitProcess = Process()
        gitProcess.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        gitProcess.arguments = ["describe", "--tags", "--always", "--dirty"]

        let standardOutput = Pipe()
        let standardError = Pipe()
        gitProcess.standardOutput = standardOutput
        gitProcess.standardError = standardError

        var gitVersion = "0.0.0-dev"
        do {
            try gitProcess.run()
            gitProcess.waitUntilExit()

            let outputData = standardOutput.fileHandleForReading.readDataToEndOfFile()
            let errorData = standardError.fileHandleForReading.readDataToEndOfFile()
            _ = errorData

            if let output = String(data: outputData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !output.isEmpty {
                // 如果标签带 'v' 前缀（例如 v0.1.0），去掉 'v'
                gitVersion = output.hasPrefix("v") ? String(output.dropFirst()) : output
            }
        } catch {
            // 如果不在 git 仓库中，或者没有可用 tag，使用默认版本号
        }
        
        let fileContent = """
        // 由 SPM GenerateVersionPlugin 自动生成，请勿手动改动
        enum AppVersion {
            static let current = "\(gitVersion)"
        }
        """
        
        return [
            .buildCommand(
                displayName: "Generating Version from Git Tag",
                executable: URL(fileURLWithPath: "/bin/sh"),
                arguments: ["-c", "mkdir -p '\(generatedSourceDir.path)' && echo '\(fileContent)' > '\(generatedFile.path)'"],
                inputFiles: [],
                outputFiles: [generatedFile]
            )
        ]
    }
}