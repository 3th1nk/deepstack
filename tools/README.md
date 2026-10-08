# tools

跨文章复用的工具。只服务单篇文章的脚本放那篇文章自己的目录下。

---

## minidump_analyzer.py

通用的 Electron / Chromium / CEF 崩溃转储分析器。

**纯 Python 直接解析 Windows minidump 的二进制结构**——不需要 Windows，不需要符号表，不需要装任何调试器。

它的定位不是替代 WinDbg，而是：**当你手边没有 Windows 环境、或者符号还没拉下来的时候，让你现在就能开工。**

### 用法

```bash
# 单个 dump
python3 minidump_analyzer.py crash.dmp

# 批量分析整个目录（自动查找同目录的 metadata.bin）
python3 minidump_analyzer.py ./crashes/ -o report.md

# 结构化输出
python3 minidump_analyzer.py crash.dmp -j result.json
```

### 参数

| 参数 | 说明 |
| --- | --- |
| `target` | `.dmp` 文件或包含 `.dmp` 的目录 |
| `-m, --metadata` | `metadata.bin` 路径（默认自动查找） |
| `-o, --output` | 输出报告到文件（Markdown/文本） |
| `-j, --json` | 输出 JSON 结果 |
| `-q, --quiet` | 精简输出（跳过字符串扫描，快很多） |
| `--max-stack` | 栈回溯最大帧数（默认 40） |
| `--no-color` | 禁用颜色 |

### 报告包含什么

| 章节 | 内容 |
| --- | --- |
| 文件信息 | 大小、MDMP 签名、崩溃时间戳、stream 数 |
| 应用与运行环境 | 框架版本、OS build、CPU、进程 ID、运行时长、CPU 时间、主模块 |
| 崩溃异常 | 异常码与名称、含义（主动触发 / 被杀）、崩溃线程 |
| 崩溃位置 | 指令地址、所属模块、模块内偏移 |
| 崩溃日志 | 从 dump 里捞出的 FATAL / ERROR 日志 |
| **Crashpad 注解** | 崩溃那一刻写进 dump 的 key-value 内部状态 |
| 崩溃线程调用栈 | 匹配模块代码段的候选帧（无符号，只有地址） |
| 内存概况 | 已提交 / 保留 / 镜像提交 |
| metadata.bin | 崩溃历史（UUID + 时间），判断是否反复出现 |
| 诊断结论 | 按优先级给出可能根因 |
| 修复建议 | 针对结论的具体做法 |

### 为什么注解比栈有用

没有符号表时，调用栈的上限就是"这几帧挨得近"，函数名一个都解析不出来。

但 Crashpad 在崩溃那一刻会把一堆内部状态以 key-value 写进 dump——这些是 Chromium 自己塞进去给上游定位用的。**栈告诉你「在哪」，注解告诉你「可能为什么」。**

实战例子见 [`articles/2026-10-electron-crash`](../articles/2026-10-electron-crash/)：栈全是裸地址，最后靠 `nav_reentrancy-*` 这组注解锁定了导航重入。
