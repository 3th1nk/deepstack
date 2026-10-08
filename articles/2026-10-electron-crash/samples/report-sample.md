==============================================================================
 Electron / Chromium 崩溃转储分析报告
==============================================================================

【1】文件信息
  路径            : ./06c54788-7389-4339-8c56-8f4843715e34.dmp
  大小            : 34.7MB (36348016 字节)
  签名 / 版本     : MDMP / 0xa793
  崩溃时间戳      : 2026-08-01 16:23:14
  Stream 数量     : 12

【2】应用与运行环境
  产品名称        : SomeApp
  应用版本        : 2.63.111-beta
  框架            : Electron 33.4.11
  进程类型        : browser
  操作系统        : Windows 10.0 Build 19045 6466
  CPU             : 28 核 / x86_64 (AMD64) (64-bit)
  进程 ID         : 30872
  进程启动        : 2026-08-01 14:52:03
  崩溃前运行时长  : 1小时31分11秒
  CPU 时间        : 用户态 311s / 内核态 245s
  主模块          : SomeApp.exe (184.0MB, 构建于 2025-04-15 22:03:27)
  主模块路径      : C:\Users\<user>\AppData\Local\Programs\<app-dir>\SomeApp.exe

【3】崩溃异常
  异常代码        : 0x80000003
  异常名称        : EXCEPTION_BREAKPOINT
  含义            : 断点/断言 — 代码主动触发（Chromium CHECK/NOTREACHED）
  崩溃线程 ID     : 28372
  不可继续        : 否

【4】崩溃位置
  崩溃指令地址    : 0x00007FF6F202F3DB
  所属模块        : SomeApp.exe
  模块路径        : C:\Users\<user>\AppData\Local\Programs\<app-dir>\SomeApp.exe
  模块基址        : 0x00007FF6EB760000
  模块内偏移      : 0x68CF3DB
  是否主模块      : 是（应用自身二进制 / Electron 内核）

【5】崩溃日志
  [FATAL] check.cc(361)
      Check failed: false. NOTREACHED log messages are omitted in official builds. Sorry!

【6】Crashpad 崩溃注解（关键上下文）
  nav_reentrancy-entries_size                   = 6
  nav_reentrancy-is_forced_reload               = false
  nav_reentrancy-is_initial_blank_nav           = false
  nav_reentrancy-is_initial_nav                 = false
  nav_reentrancy-last_committed_index           = 5
  nav_reentrancy-pending_entry_id               = 183
  nav_reentrancy-pending_entry_index            = 5
  nav_reentrancy-pending_entry_initial          = false
  nav_reentrancy-pending_entry_initial2         = false
  nav_reentrancy-pending_entry_restored         = false
  nav_reentrancy-pending_reload_type            = 0
  nav_reentrancy-prev_pending_entry_id          = 183
  nav_reentrancy_caller1-Reload_type            = 1
  --- 其他 ---
  _productName                                  = SomeApp
  _version                                      = 2.63.111-beta
  osarch                                        = x86_64
  pid                                           = 30872
  plat                                          = Win64
  platform                                      = win32
  process_type                                  = browser
  prod                                          = Electron
  ptype                                         = browser
  total-discardable-memory-allocated            = 0
  ver                                           = 33.4.11

【7】崩溃线程调用栈（候选帧，无符号表）
  说明：以下为栈内存中匹配到模块代码段的返回地址，需 PDB 符号才能解析函数名

    SP+0x0488  0x00007FF6ED185436  SomeApp.exe+0x1A25436
    SP+0x0500  0x00007FF6F564B141  SomeApp.exe+0x9EEB141
    SP+0x0578  0x00007FF6ED184EA8  SomeApp.exe+0x1A24EA8
    SP+0x0598  0x00007FF6EB96B3FF  SomeApp.exe+0x20B3FF
    SP+0x05B8  0x00007FF6ED197D6C  SomeApp.exe+0x1A37D6C
    SP+0x05E8  0x00007FF6EB96B3FF  SomeApp.exe+0x20B3FF
    SP+0x0628  0x00007FF6F2031C6C  SomeApp.exe+0x68D1C6C  <== 紧邻崩溃点
    SP+0x0668  0x00007FF6F2031DAC  SomeApp.exe+0x68D1DAC  <== 紧邻崩溃点
    SP+0x0678  0x00007FF6ECC7403C  SomeApp.exe+0x151403C
    SP+0x0698  0x00007FF6F564B14F  SomeApp.exe+0x9EEB14F
    SP+0x06A0  0x00007FF6F564B141  SomeApp.exe+0x9EEB141
    SP+0x06B0  0x00007FF6F2031D76  SomeApp.exe+0x68D1D76  <== 紧邻崩溃点
    SP+0x06D8  0x00007FF6EFF45C09  SomeApp.exe+0x47E5C09
    SP+0x0708  0x00007FF6ECC878CB  SomeApp.exe+0x15278CB
    SP+0x0718  0x00007FF6ED4F3109  SomeApp.exe+0x1D93109
    SP+0x07D8  0x00007FF6ECBACFB9  SomeApp.exe+0x144CFB9
    SP+0x07E8  0x00007FF6ECB6E7C2  SomeApp.exe+0x140E7C2
    SP+0x0858  0x00007FF6EF78D000  SomeApp.exe+0x402D000
    SP+0x0908  0x00007FF6EC94731F  SomeApp.exe+0x11E731F
    SP+0x0918  0x00007FF6ECAE7B00  SomeApp.exe+0x1387B00
    SP+0x0938  0x00007FF6EF73FB01  SomeApp.exe+0x3FDFB01
    SP+0x0940  0x00007FF6F5221900  SomeApp.exe+0x9AC1900
    SP+0x0948  0x00007FF6EF73FB01  SomeApp.exe+0x3FDFB01
    SP+0x09A8  0x00007FF6ECBB028A  SomeApp.exe+0x145028A
    SP+0x0A38  0x00007FF6ECBAF110  SomeApp.exe+0x144F110
    SP+0x0B18  0x00007FF6ECB3AE29  SomeApp.exe+0x13DAE29
    SP+0x0BA0  0x00007FF6F53B60DA  SomeApp.exe+0x9C560DA
    SP+0x0D50  0x00007FF6F6658940  SomeApp.exe+0xAEF8940
    SP+0x0D58  0x00007FF6ED1A51A6  SomeApp.exe+0x1A451A6
    SP+0x0DA0  0x00007FF6F6658940  SomeApp.exe+0xAEF8940

【8】内存概况（崩溃时进程地址空间）
  已提交内存      : 1.2GB
  保留内存        : 3.1TB
  镜像(代码)提交  : 294.0MB
  内存区域数      : 26938

【9】metadata.bin — 崩溃历史
  路径            : ./metadata.bin
  格式 / 版本     : DAPC / v1
  声明记录数      : 3
  提取到 dump 数  : 3
    [0] d3da3a4d-ee7f-493d-8963-85bd5e12f70c  2026-07-28 08:19:06
    [1] 6e622789-b2d9-47a7-8b77-81f578d6acb0  2026-07-30 16:22:44
    [2] 06c54788-7389-4339-8c56-8f4843715e34  2026-08-01 16:23:18

  ⚠ 存在多次崩溃记录，说明该问题是反复出现的稳定性缺陷，
    建议收集全部 dump 对比是否为同一根因。

【10】诊断结论
  崩溃进程类型    : browser — 浏览器进程（主进程）— 崩溃会导致整个应用退出

  ● Chromium NOTREACHED()/CHECK() 断言失败   [P1]
    崩溃由 Chromium 内部断言触发（CHECK()/NOTREACHED()/DCHECK()）。
   自 Chromium 128（Electron 33 起）NOTREACHED() 在正式版中由「静默忽略」
   变更为「CHECK(false) 致命终止」，导致此前被忽略的边界路径现在直接闪退。
   这是 Electron ≥33 最典型的非资源型崩溃来源。

  ⚠ 导航重入专项提示
      nav_reentrancy-prev_pending_entry_id          = 183
      nav_reentrancy-pending_reload_type            = 0
      nav_reentrancy-is_forced_reload               = false
      nav_reentrancy-is_initial_blank_nav           = false
      nav_reentrancy-is_initial_nav                 = false
      nav_reentrancy-pending_entry_initial2         = false
      nav_reentrancy-pending_entry_initial          = false
      nav_reentrancy-entries_size                   = 6
      nav_reentrancy-last_committed_index           = 5
      nav_reentrancy-pending_entry_index            = 5
      nav_reentrancy-pending_entry_id               = 183
      nav_reentrancy-pending_entry_restored         = false
    检测到导航重入相关注解。典型诱因：在页面导航未完成（did-start-navigation 之后、did-finish-load 之前）又发起了 reload()/loadURL()/location 跳转，包括注入 JS 中的 location.reload()/location.href 赋值，或定时器自动刷新。

【11】修复建议
  1. 确认 Electron 版本：≥33 需特别关注断言类崩溃，建议升级到 35+
  2. 在应用侧避免触发该断言的非法调用（见下方 process_type 相关建议）
  3. 不要 patch Chromium 源码绕过断言，会掩盖更严重的状态不一致
  4. 在 reload()/loadURL() 前加入导航状态守卫（did-start-navigation 置位、
     did-finish-load / did-fail-load 复位），避免导航过程中重复触发导航
  5. 审查注入 JS：禁止在页面加载期调用 location.reload()/location.href 赋值
  6. 定时器自动刷新改为事件驱动 + 冷却时间，避免与用户操作叠加

==============================================================================
 说明：本报告为静态二进制解析结果。若需函数级调用栈，请在 Windows 上使用
       WinDbg/cdb 加载与主模块版本完全一致的 PDB 符号文件后执行:
         !analyze -v      （自动分析）
         kP               （打印带参数的调用栈）
==============================================================================