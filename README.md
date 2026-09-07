# kc-util

Keychain complement tools to `security` command

```
.
├── Package.swift
├── Plugins
│   └── GenerateVersion
│       └── plugin.swift
├── Sources
│   ├── KeychainKit                   # 🟢 1. 拆分出的核心 Service 库 (Library Target)
│   │   ├── Models
│   │   │   ├── CertificateDetail.swift
│   │   │   └── CertificateSummary.swift
│   │   ├── KeychainError.swift
│   │   └── KeychainService.swift     # 安全/Keychain 交互核心逻辑
│   │
│   └── kc-util                       # 🔵 2. 可执行命令行工具 (Executable Target)
│       ├── Commands
│       │   ├── Cert
│       │   │   ├── Cert.swift        # cert 子命令组
│       │   │   ├── CertFindByFp.swift# cert find 子命令
│       │   │   └── CertLs.swift      # cert ls 子命令
│       │   └── RootCommand.swift     # 根命令配置
│       ├── Formatters                # 终端表格/输出格式化组件
│       │   └── TableFormatter.swift
│       ├── Extensions
│       │   └── String+Padding.swift  # 字符串对齐等辅助函数
│       └── main.swift                # CLI 入口脚本 (或 KcUtil.swift @main)
│
└── Tests
    ├── KeychainKitTests              # 🟢 针对核心逻辑的单元测试 (无需通过 CLI 测试)
    │   └── KeychainServiceTests.swift
    └── kc-utilTests                  # 🔵 针对命令行端到端（E2E）或参数解析的测试
        └── ArgumentParsingTests.swift
```