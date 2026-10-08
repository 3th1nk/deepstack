# 不挂符号的时候，崩溃栈该怎么读

> 关联文章：公众号「栈深处」· #崩溃现场 01
> 一句话结论：**根因不在栈里，在栈旁边。**

一个 Windows 上的 Electron 应用（Electron 33.4.11 / Chromium 130）反复闪退，没有弹窗、没有日志。崩溃栈 20 层全是裸地址，一个函数名都解析不出来——最后靠 Crashpad 注解锁定的方向。

---

## 一 · 问题

| 项 | 值 |
| --- | --- |
| 现象 | 用着用着窗口就没了，无提示、无日志。有时一小时，有时更久 |
| 环境 | Electron 33.4.11 / Chromium 130 / Win10 22H2 |
| 手上的材料 | 一个 `.dmp` + 一个 `metadata.bin`（Crashpad 留在用户目录下的） |
| 约束 | 分析机是 macOS，没挂符号 |

## 二 · 结论

1. **异常码 `0x80000003` = 代码主动触发**，不是访问违例。`CHECK()` / `NOTREACHED()` 失败 → `base::ImmediateCrash()` → `__debugbreak()`。程序没越界，它是判断"这里不该发生"然后自杀的。
2. FATAL 日志 `check.cc(361): Check failed: false` + `NOTREACHED log messages are omitted in official builds. Sorry!` —— 正式版把具体信息裁掉了。
3. **栈读不出来时看注解。** `nav_reentrancy-pending_entry_id = 183` 与 `prev_pending_entry_id = 183` 相同，说明上一次导航还没结束新的就来了。
4. **以前不崩是因为 NOTREACHED() 语义变了。** Chromium 在 128~130 前后把它从「正式版展开成 `DCHECK(false)` 的空操作」渐进迁移为带 `[[noreturn]]` 的致命检查。**代码一直都在重入，只是以前没人管它。**

## 三 · 复现

拿到自己的 dump 后：

```bash
# 1. 下载工具
curl -O https://raw.githubusercontent.com/3th1nk/deepstack/main/tools/minidump_analyzer.py

# 2. 跑（把 .dmp 和 metadata.bin 放同一个目录）
python3 minidump_analyzer.py ./crashes/ -o report.md

# 3. 看报告 §6 注解、§9 崩溃历史
```

完整输出示例见 [`samples/report-sample.md`](samples/report-sample.md)（真实 dump 跑出来的，已脱敏）。

想看函数级调用栈，还是得在 Windows 上用 WinDbg 挂 `https://symbols.electronjs.org` 的 PDB——但多数情况下注解已经够指明方向了。

## 四 · 修复方向

| # | 做法 |
| --- | --- |
| 1 | 加导航状态守卫：`did-start-navigation` 置位，`did-finish-load` / `did-fail-load` 复位 |
| 2 | 定时器 reload 改成事件驱动（原来 30 秒一次 `setInterval`，是重入来源之一） |
| 3 | reload 加冷却（2 秒内不重复触发） |
| 4 | 升级 Electron（34 修了一部分导航断言，35+ 更稳） |
| 5 | 开 `crashReporter.start()` 并记导航日志——这次能查全靠 Crashpad 恰好留了 dump，那是运气不是机制 |
| 6 | 别对 `did-start-navigation` 调 `preventDefault()`，它是通知型事件拦不住；能拦的是 `will-navigate` / `will-frame-navigate` / `will-redirect` |

## 五 · 文件

| 路径 | 说明 |
| --- | --- |
| `figures/` | 文章配图（4 张内文图 + 封面），含 SVG 源与 @2x PNG |
| `samples/metadata.bin` | Crashpad 的崩溃历史文件（310 字节，DAPC 格式，记了 3 次崩溃） |
| `samples/report-sample.md` | 脚本对真实 dump 的完整输出示例（已脱敏） |

**为什么没有 `.dmp`**：原始 dump 有 34.7MB，且含真实内存内容（用户路径、内存片段），不适合入库。想试的话拿自己的 dump 跑，或者用 `samples/metadata.bin` 看崩溃历史部分。

**脱敏说明**：应用名 → `SomeApp`，Windows 用户名 → `<user>`，安装路径 → `<app-dir>`，本地绝对路径已去掉。
