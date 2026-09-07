import PackagePlugin
import Foundation

@main
struct GenerateVersionPlugin: BuildToolPlugin {
    func createBuildCommands(context: PluginContext, target: Target) async throws -> [Command] {
        let generatedSourceDir = context.pluginWorkDirectoryURL.appending(path: "GeneratedSources")
        let generatedFile = generatedSourceDir.appending(path: "Version.g.swift")
        
        // 尝试通过 git describe 获取最新 Tag，失败时回退到开发版本 0.0.0-dev
        let gitProcess = Process()
        gitProcess.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        gitProcess.arguments = ["describe", "--tags", "--always", "--dirty"]
        
        let pipe = Pipe()
        gitProcess.standardOutput = pipe
        
        var gitVersion = "0.0.0-dev"
        do {
            try gitProcess.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !output.isEmpty {
                // 如果标签带 'v' 前缀（例如 v0.1.0），去掉 'v'
                gitVersion = output.hasPrefix("v") ? String(output.dropFirst()) : output
            }
        } catch {
            // 如果不在 git 仓库中，使用默认版本号
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