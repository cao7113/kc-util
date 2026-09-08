# kc-util

Keychain complement tools to `security` command


## Debug

```
# 1. 使用 Release 模式编译并运行
swift run -c release kc-util cert find-by-fp e57dbe3b62c0df5c24e05468ded5026b85a1d2a0

# 2. 若直接运行复现了 trace trap，使用 LLDB 调试 Release 产物
lldb -- .build/release/kc-util cert find-by-fp e57dbe3b62c0df5c24e05468ded5026b85a1d2a0
(lldb) r
# 崩溃后查看调用栈
(lldb) bt
```