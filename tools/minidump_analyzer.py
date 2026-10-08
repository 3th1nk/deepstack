#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
minidump_analyzer.py — 通用 Electron / Chromium / CEF 崩溃转储分析器

解析 Windows Minidump (.dmp) 与 Crashpad metadata.bin，输出结构化中文诊断报告。
适用于 Electron、CEF、Chromium Embedded 及任何使用 Crashpad/Breakpad 的应用。

用法:
    python3 minidump_analyzer.py <crash.dmp>
    python3 minidump_analyzer.py <crash.dmp> -o report.md
    python3 minidump_analyzer.py <crash.dmp> -m metadata.bin --json result.json
    python3 minidump_analyzer.py ./crash_dir/            # 批量分析目录下所有 .dmp

选项:
    -m, --metadata PATH    metadata.bin 路径（默认自动查找同目录）
    -o, --output PATH      输出 Markdown 报告到文件
    -j, --json PATH        输出 JSON 结构化结果
    -q, --quiet            精简输出（跳过字符串扫描与栈回溯）
    --max-stack N          栈回溯最大候选帧数（默认 40）
    --no-color             禁用 ANSI 颜色

限制说明:
    - 无 PDB 符号文件时，调用栈只能解析到「模块 + 偏移」，无法得到函数名。
      需要函数级栈请用 WinDbg/cdb 加载对应版本的 PDB（见报告末尾说明）。
    - 本工具只做静态解析，不连接网络、不下载符号。
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import struct
import sys

# ============================================================================
# 常量定义
# ============================================================================

# --- Minidump Stream 类型 ---
STREAM_TYPES = {
    0: "Unused",
    1: "Reserved0",
    2: "Reserved1",
    3: "ThreadList",
    4: "ModuleList",
    5: "MemoryList",
    6: "Exception",
    7: "SystemInfo",
    8: "ThreadExList",
    9: "Memory64List",
    10: "CommentA",
    11: "CommentW",
    12: "HandleData",
    13: "FunctionTable",
    14: "UnloadedModuleList",
    15: "MiscInfo",
    16: "MemoryInfoList",
    17: "ThreadInfoList",
    18: "HandleOperationList",
    19: "Token",
    20: "JavaScriptData",
    21: "SystemMemoryInfo",
    22: "ProcessVmCounters",
    23: "IptTrace",
    24: "ThreadNames",
}

# --- Windows 异常码 ---
EXCEPTION_CODES = {
    0x80000003: ("EXCEPTION_BREAKPOINT", "断点/断言 — 代码主动触发（Chromium CHECK/NOTREACHED）"),
    0x80000004: ("EXCEPTION_SINGLE_STEP", "单步断点"),
    0xC0000005: ("EXCEPTION_ACCESS_VIOLATION", "内存访问违例（空指针/野指针/越界）"),
    0xC0000006: ("EXCEPTION_IN_PAGE_ERROR", "页面内错误（读取映射文件失败）"),
    0xC000001D: ("EXCEPTION_ILLEGAL_INSTRUCTION", "非法指令"),
    0xC0000025: ("EXCEPTION_NONCONTINUABLE", "不可继续执行的异常"),
    0xC0000026: ("EXCEPTION_INVALID_DISPOSITION", "无效的异常处置"),
    0xC000008C: ("EXCEPTION_ARRAY_BOUNDS_EXCEEDED", "数组越界"),
    0xC000008D: ("EXCEPTION_FLT_DIVIDE_BY_ZERO", "浮点除零"),
    0xC000008E: ("EXCEPTION_FLT_INEXACT_RESULT", "浮点结果不精确"),
    0xC000008F: ("EXCEPTION_FLT_INVALID_OPERATION", "浮点无效操作"),
    0xC0000090: ("EXCEPTION_FLT_OVERFLOW", "浮点溢出"),
    0xC0000091: ("EXCEPTION_FLT_STACK_CHECK", "浮点栈检查失败"),
    0xC0000092: ("EXCEPTION_FLT_UNDERFLOW", "浮点下溢"),
    0xC0000093: ("EXCEPTION_INT_OVERFLOW", "整数溢出"),
    0xC0000094: ("EXCEPTION_INT_DIVIDE_BY_ZERO", "整数除零"),
    0xC0000095: ("EXCEPTION_INT_OVERFLOW2", "整数溢出"),
    0xC0000096: ("EXCEPTION_PRIV_INSTRUCTION", "特权指令"),
    0xC00000FD: ("EXCEPTION_STACK_OVERFLOW", "栈溢出（无限递归/栈上大对象）"),
    0xC0000135: ("STATUS_DLL_NOT_FOUND", "DLL 未找到"),
    0xC000013A: ("STATUS_CONTROL_C_EXIT", "进程被 Ctrl+C 终止"),
    0xC0000142: ("STATUS_DLL_INIT_FAILED", "DLL 初始化失败"),
    0xC0000374: ("STATUS_HEAP_CORRUPTION", "堆损坏"),
    0xC0000409: ("STATUS_STACK_BUFFER_OVERRUN", "栈缓冲区溢出（/GS 保护触发）"),
    0xC0000417: ("STATUS_INVALID_CRUNTIME_PARAMETER", "无效的 CRT 参数"),
    0xC000041D: ("STATUS_FATAL_USER_CALLBACK_EXCEPTION", "用户回调未处理异常"),
    0xC0000420: ("STATUS_ASSERTION_FAILURE", "断言失败"),
    0xC0000602: ("STATUS_FAIL_FAST_EXCEPTION", "Fail Fast 异常（__fastfail）"),
    0xE0434352: ("CLR_EXCEPTION", ".NET CLR 异常"),
    0xE06D7363: ("CPP_EXCEPTION", "C++ 异常（Microsoft C++ EH，未捕获）"),
    0xE0EDFADE: ("DELPHI_EXCEPTION", "Delphi 异常"),
}

# --- CPU 架构 ---
ARCH_NAMES = {
    0: ("x86", "32-bit"),
    9: ("x86_64 (AMD64)", "64-bit"),
    5: ("ARM", "32-bit"),
    12: ("ARM64", "64-bit"),
    6: ("IA64", "64-bit"),
}

# --- Windows 产品类型 ---
PRODUCT_TYPES = {
    1: "Workstation（客户端）",
    2: "Domain Controller",
    3: "Server",
}

# --- 内存状态/类型 ---
MEM_STATES = {0x1000: "COMMIT", 0x2000: "RESERVE", 0x10000: "FREE"}
MEM_TYPES = {0x20000: "PRIVATE", 0x40000: "MAPPED", 0x1000000: "IMAGE"}

# --- Chromium 进程类型说明 ---
PROCESS_TYPE_DESC = {
    "browser": "浏览器进程（主进程）— 崩溃会导致整个应用退出",
    "renderer": "渲染进程 — 通常只影响单个页面/窗口",
    "gpu": "GPU 进程 — 图形/硬件加速相关",
    "utility": "工具进程 — 网络、音频、转码等",
    "plugin": "插件进程",
    "ppapi": "PPAPI 插件进程",
    "zygote": "Zygote 进程（Linux 孵化器）",
    "crashpad": "Crashpad 处理器进程",
    "sandbox": "沙箱辅助进程",
}

# --- 崩溃模式库：根据证据给出诊断 ---
CRASH_PATTERNS = [
    {
        "id": "notreached",
        "title": "Chromium NOTREACHED()/CHECK() 断言失败",
        "severity": "P1",
        "test": lambda c: (
            c["exception_code"] == 0x80000003
            or "NOTREACHED" in c["log_blob"]
            or "Check failed" in c["log_blob"]
        ),
        "detail": (
            "崩溃由 Chromium 内部断言触发（CHECK()/NOTREACHED()/DCHECK()）。\n"
            "   自 Chromium 128（Electron 33 起）NOTREACHED() 在正式版中由「静默忽略」\n"
            "   变更为「CHECK(false) 致命终止」，导致此前被忽略的边界路径现在直接闪退。\n"
            "   这是 Electron ≥33 最典型的非资源型崩溃来源。"
        ),
        "actions": [
            "确认 Electron 版本：≥33 需特别关注断言类崩溃，建议升级到 35+",
            "在应用侧避免触发该断言的非法调用（见下方 process_type 相关建议）",
            "不要 patch Chromium 源码绕过断言，会掩盖更严重的状态不一致",
        ],
    },
    {
        "id": "oom",
        "title": "内存不足（OOM）",
        "severity": "P1",
        "test": lambda c: (
            "out of memory" in c["log_blob"].lower()
            or "oom" in c["log_blob"].lower()
            or c.get("exception_code") == 0xC0000005 and "base::allocator" in c["log_blob"]
        ),
        "detail": "进程耗尽可用内存/地址空间，分配器无法满足请求。",
        "actions": [
            "检查渲染进程内存泄漏：DOM 节点未释放、事件监听未解绑、大数组常驻",
            "检查 JS 注入脚本是否持有大量对象引用",
            "考虑限制同时打开的窗口/标签数量，启用后台标签页内存回收",
        ],
    },
    {
        "id": "stack_overflow",
        "title": "栈溢出",
        "severity": "P1",
        "test": lambda c: c.get("exception_code") in (0xC00000FD, 0xC0000409),
        "detail": "调用栈深度超出线程栈上限，通常由无限递归或栈上分配超大对象引起。",
        "actions": [
            "检查注入 JS 是否存在互相调用导致的无限递归（如 A 事件触发 B、B 又触发 A）",
            "检查 MutationObserver / Object.defineProperty 递归陷阱",
            "避免在主进程同步递归调用 IPC",
        ],
    },
    {
        "id": "heap_corruption",
        "title": "堆损坏",
        "severity": "P0",
        "test": lambda c: c.get("exception_code") in (0xC0000374,),
        "detail": "堆元数据被破坏，通常由缓冲区溢出、double-free、use-after-free 引起。",
        "actions": [
            "若加载了原生模块（.node），重点排查其内存管理",
            "开启 PageHeap / ASan 复现定位",
        ],
    },
    {
        "id": "access_violation",
        "title": "内存访问违例",
        "severity": "P1",
        "test": lambda c: c.get("exception_code") == 0xC0000005,
        "detail": "访问了无效内存地址（空指针、已释放对象、越界）。",
        "actions": [
            "结合崩溃地址所属模块判断是否第三方模块问题",
            "若为 GPU 相关模块，尝试 app.disableHardwareAcceleration() 排查",
            "检查 webContents 生命周期：窗口关闭后仍被调用",
        ],
    },
]

# --- 导航重入相关注解键（Electron 浏览器自定义场景）---
NAV_HINT_KEYS = ("nav_reentrancy", "nav_", "navigation")


# ============================================================================
# 工具函数
# ============================================================================


def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0]


def fmt_ts(ts: int) -> str:
    """Unix 时间戳 -> 可读字符串"""
    if not ts or ts > 4102444800:  # > 2100 年视为无效
        return "N/A"
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


def basename(path: str) -> str:
    """同时处理 Windows / POSIX 路径"""
    return os.path.basename(path.replace("\\", "/"))


def format_guid(raw: bytes) -> str:
    """按 Windows GUID 混合字节序解析 16 字节 UUID"""
    if len(raw) < 16:
        return ""
    d1 = _u32(raw, 0)
    d2 = _u16(raw, 4)
    d3 = _u16(raw, 6)
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{raw[8:10].hex()}-{raw[10:16].hex()}"


class Color:
    """简易 ANSI 颜色（可用 --no-color 关闭）"""

    enabled = True

    @classmethod
    def _w(cls, code, text):
        if not cls.enabled:
            return str(text)
        return f"\033[{code}m{text}\033[0m"

    @classmethod
    def red(cls, t):
        return cls._w("91", t)

    @classmethod
    def green(cls, t):
        return cls._w("92", t)

    @classmethod
    def yellow(cls, t):
        return cls._w("93", t)

    @classmethod
    def blue(cls, t):
        return cls._w("94", t)

    @classmethod
    def cyan(cls, t):
        return cls._w("96", t)

    @classmethod
    def bold(cls, t):
        return cls._w("1", t)


# ============================================================================
# 核心分析器
# ============================================================================


class MinidumpAnalyzer:
    """通用 Windows Minidump 解析器"""

    def __init__(self, path: str, max_stack: int = 40, deep: bool = True):
        self.path = path
        self.max_stack = max_stack
        self.deep = deep
        with open(path, "rb") as f:
            self.data = f.read()
        self.result: dict = {}
        self._strings: list[tuple[int, str]] = []

    # ---------- 入口 ----------
    def analyze(self) -> dict:
        if self.data[:4] != b"MDMP":
            raise ValueError(f"不是有效的 Minidump 文件（magic={self.data[:4]!r}）")

        self._parse_header()
        self._parse_streams()
        self._parse_system_info()
        self._parse_misc_info()
        self._parse_exception()
        self._parse_modules()
        self._parse_threads()
        self._parse_memory_info()
        if self.deep:
            self._scan_strings()
            self._extract_log_and_annotations()
        self._locate_crash_address()
        self._unwind_stack()
        self._diagnose()
        return self.result

    # ---------- Header / Stream Directory ----------
    def _parse_header(self):
        d = self.data
        self.result["file"] = {
            "path": self.path,
            "size": len(d),
            "size_human": human_size(len(d)),
            "signature": d[:4].decode("ascii", "replace"),
            "version": f"0x{_u32(d, 4):x}",
            "timestamp_raw": _u32(d, 20),
            "timestamp": fmt_ts(_u32(d, 20)),
            "flags": f"0x{_u64(d, 24):x}",
        }
        self.num_streams = _u32(d, 8)
        self.stream_dir_rva = _u32(d, 12)
        self.result["file"]["stream_count"] = self.num_streams

    def _parse_streams(self):
        """动态解析 Stream Directory —— 关键：不再硬编码 RVA"""
        self.streams = {}
        entries = []
        for i in range(self.num_streams):
            off = self.stream_dir_rva + i * 12
            if off + 12 > len(self.data):
                break
            st = _u32(self.data, off)
            size = _u32(self.data, off + 4)
            rva = _u32(self.data, off + 8)
            self.streams[st] = (size, rva)
            entries.append(
                {"index": i, "type": st, "name": STREAM_TYPES.get(st, f"Custom({st})"),
                 "size": size, "rva": rva}
            )
        self.result["streams"] = entries

    def _stream(self, st):
        """安全获取 stream (size, rva)"""
        return self.streams.get(st)

    # ---------- SystemInfo ----------
    def _parse_system_info(self):
        s = self._stream(7)
        info = {}
        if not s:
            self.result["system"] = info
            return
        size, rva = s
        if rva + 32 > len(self.data):
            self.result["system"] = info
            return

        arch = _u16(self.data, rva)
        num_cpus = self.data[rva + 6]
        product = self.data[rva + 7]
        major = _u32(self.data, rva + 8)
        minor = _u32(self.data, rva + 12)
        build = _u32(self.data, rva + 16)

        arch_name, bits = ARCH_NAMES.get(arch, (f"Unknown({arch})", "?"))
        info.update({
            "architecture": arch_name,
            "bits": bits,
            "cpu_count": num_cpus,
            "product_type": PRODUCT_TYPES.get(product, f"Unknown({product})"),
            "os_major": major,
            "os_minor": minor,
            "os_build": build,
            "os_version": f"{major}.{minor} Build {build}",
        })
        self.arch = arch
        self.bits = bits

        # CSDVersion (UTF-16LE)，偏移 +24 是 RVA
        csd_rva = _u32(self.data, rva + 24)
        if 0 < csd_rva < len(self.data) - 4:
            try:
                ln = _u32(self.data, csd_rva)
                info["service_pack"] = self.data[csd_rva + 4: csd_rva + 4 + ln].decode(
                    "utf-16-le", "replace")
            except Exception:
                pass

        # CPU Vendor 位于 CPU_INFORMATION（结构起始 +32），12 字节
        if rva + 44 <= len(self.data):
            vendor = self.data[rva + 32: rva + 44]
            try:
                v = vendor.decode("ascii", "replace").rstrip("\x00").strip()
                if v and v.isprintable():
                    info["cpu_vendor"] = v
            except Exception:
                pass

        self.result["system"] = info

    # ---------- MiscInfo ----------
    def _parse_misc_info(self):
        s = self._stream(15)
        info = {}
        if s:
            size, rva = s
            if _u32(self.data, rva) >= 24 and rva + 24 <= len(self.data):
                info["process_id"] = _u32(self.data, rva + 8)
                info["process_created"] = fmt_ts(_u32(self.data, rva + 12))
                info["process_created_ts"] = _u32(self.data, rva + 12)
                info["user_time_sec"] = _u32(self.data, rva + 16)
                info["kernel_time_sec"] = _u32(self.data, rva + 20)
                # 运行时长（若崩溃时间戳可用）
                created = _u32(self.data, rva + 12)
                crash_ts = self.result["file"]["timestamp_raw"]
                if created and crash_ts and crash_ts > created:
                    dur = crash_ts - created
                    h, rem = divmod(dur, 3600)
                    m, sec = divmod(rem, 60)
                    info["uptime"] = f"{h}小时{m}分{sec}秒" if h else f"{m}分{sec}秒"
        self.result["process"] = info

    # ---------- Exception ----------
    def _parse_exception(self):
        s = self._stream(6)
        info = {"present": False}
        self.crashing_thread_id = None
        if s:
            size, rva = s
            if rva + 8 + 152 <= len(self.data):
                tid = _u32(self.data, rva)
                e = rva + 8  # MINIDUMP_EXCEPTION 起始
                code = _u32(self.data, e)
                flags = _u32(self.data, e + 4)
                addr = _u64(self.data, e + 16)
                nparams = _u32(self.data, e + 24)

                name, desc = EXCEPTION_CODES.get(code, (f"0x{code:08X}", "未知异常"))
                info.update({
                    "present": True,
                    "thread_id": tid,
                    "code": code,
                    "code_hex": f"0x{code:08X}",
                    "name": name,
                    "description": desc,
                    "flags": flags,
                    "noncontinuable": bool(flags & 1),
                    "address": addr,
                    "address_hex": f"0x{addr:016X}",
                    "params": [],
                })
                self.crashing_thread_id = tid
                self.exception_code = code

                for i in range(min(nparams, 15)):
                    p = _u64(self.data, e + 32 + i * 8)
                    info["params"].append(p)

                # 访问违例语义
                if code == 0xC0000005 and nparams >= 2:
                    op = info["params"][0]
                    info["access_type"] = {0: "读取 (read)", 1: "写入 (write)",
                                           8: "执行 (DEP)"}.get(op, f"未知({op})")
                    info["fault_address"] = f"0x{info['params'][1]:016X}"

                # 线程上下文（寄存器）
                ctx_off = e + 152
                ctx_size = _u32(self.data, ctx_off)
                ctx_rva = _u32(self.data, ctx_off + 4)
                self.crash_ctx = (ctx_size, ctx_rva)
                info["context"] = self._parse_context(ctx_size, ctx_rva)
        self.result["exception"] = info

    def _parse_context(self, size: int, rva: int) -> dict:
        """按架构解析线程上下文寄存器"""
        regs = {}
        if not size or not rva or rva + size > len(self.data):
            return regs
        try:
            arch = getattr(self, "arch", 9)
            if arch == 9 or arch == 6:  # AMD64 / IA64
                base = rva + 120  # 跳过 P*Home + Flags + Seg + Dr*
                names = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
                for i, n in enumerate(names):
                    regs[n] = _u64(self.data, base + i * 8)
                regs["rip"] = _u64(self.data, base + 128)
            elif arch == 0:  # x86
                base = rva + 156
                names = ["edi", "esi", "ebx", "edx", "ecx", "eax", "ebp",
                         "eip", "cs", "eflags", "esp", "ss"]
                for i, n in enumerate(names):
                    regs[n] = _u32(self.data, base + i * 4)
            elif arch == 12:  # ARM64
                base = rva + 8
                for i in range(29):
                    regs[f"x{i}"] = _u64(self.data, base + i * 8)
                regs["fp"] = _u64(self.data, base + 29 * 8)   # x29
                regs["lr"] = _u64(self.data, base + 30 * 8)   # x30
                regs["sp"] = _u64(self.data, base + 31 * 8)
                regs["pc"] = _u64(self.data, base + 32 * 8)
        except Exception:
            pass
        return regs

    # ---------- Modules ----------
    def _parse_modules(self):
        s = self._stream(4)
        modules = []
        if s:
            size, rva = s
            n = _u32(self.data, rva)
            for i in range(n):
                off = rva + 4 + i * 108
                if off + 108 > len(self.data):
                    break
                base = _u64(self.data, off)
                img_size = _u32(self.data, off + 8)
                ts = _u32(self.data, off + 16)
                name_rva = _u32(self.data, off + 20)
                full = ""
                try:
                    ln = _u32(self.data, name_rva)
                    full = self.data[name_rva + 4: name_rva + 4 + ln].decode(
                        "utf-16-le", "replace").rstrip("\x00")
                except Exception:
                    pass
                modules.append({
                    "index": i,
                    "name": basename(full),
                    "path": full,
                    "base": base,
                    "size": img_size,
                    "end": base + img_size,
                    "build_time": fmt_ts(ts) if 0 < ts < 4102444800 else "N/A",
                })
        self.modules = modules
        self.result["module_count"] = len(modules)
        # 主模块（通常是 exe / 第一个模块）
        if modules:
            exe = next((m for m in modules if m["name"].lower().endswith(".exe")), modules[0])
            self.result["main_module"] = exe
        self.result["modules"] = modules

    # ---------- Threads ----------
    def _parse_threads(self):
        s = self._stream(3)
        threads = []
        if s:
            size, rva = s
            n = _u32(self.data, rva)
            for i in range(n):
                off = rva + 4 + i * 48
                if off + 48 > len(self.data):
                    break
                tid = _u32(self.data, off)
                stack_start = _u64(self.data, off + 24)
                stack_size = _u32(self.data, off + 32)
                stack_rva = _u32(self.data, off + 36)
                threads.append({
                    "index": i,
                    "id": tid,
                    "priority": _u32(self.data, off + 12),
                    "priority_class": _u32(self.data, off + 8),
                    "suspend_count": _u32(self.data, off + 4),
                    "teb": _u64(self.data, off + 16),
                    "stack_start": stack_start,
                    "stack_size": stack_size,
                    "stack_rva": stack_rva,
                    "crashing": tid == self.crashing_thread_id,
                })
            self.crash_thread = next((t for t in threads if t["crashing"]), None)
        self.threads = threads
        self.result["thread_count"] = len(threads)
        self.result["threads"] = threads

    # ---------- Memory Info ----------
    def _parse_memory_info(self):
        s = self._stream(16)
        info = {"present": False}
        if s:
            size, rva = s
            if rva + 16 <= len(self.data):
                hdr = _u32(self.data, rva)
                entry = _u32(self.data, rva + 4)
                n = _u64(self.data, rva + 8)
                if entry == 48 and n > 0 and n < 500000:
                    total_commit = 0
                    total_reserve = 0
                    image_commit = 0
                    base_off = rva + hdr
                    for i in range(int(n)):
                        o = base_off + i * 48
                        if o + 48 > len(self.data):
                            break
                        # MINIDUMP_MEMORY_INFO:
                        #   BaseAddress(8) AllocationBase(8) AllocationProtect(4) align(4)
                        #   RegionSize(8) State(4) Protect(4) Type(4) align(4)
                        region = _u64(self.data, o + 24)   # RegionSize @ +24
                        state = _u32(self.data, o + 32)    # State      @ +32
                        mtype = _u32(self.data, o + 40)    # Type       @ +40
                        if state == 0x1000:  # MEM_COMMIT
                            total_commit += region
                            if mtype == 0x1000000:
                                image_commit += region
                        elif state == 0x2000:
                            total_reserve += region
                    info.update({
                        "present": True,
                        "region_count": int(n),
                        "commit_bytes": total_commit,
                        "commit_human": human_size(total_commit),
                        "reserve_bytes": total_reserve,
                        "reserve_human": human_size(total_reserve),
                        "image_commit_human": human_size(image_commit),
                    })
        self.result["memory"] = info

    # ---------- 字符串扫描（崩溃日志 / 注解）----------
    def _scan_strings(self):
        """提取所有长度 >= 4 的可打印 ASCII 字符串及其偏移"""
        pat = re.compile(rb"[\x20-\x7e]{4,}")
        self._strings = [
            (m.start(), m.group().decode("ascii", "replace"))
            for m in pat.finditer(self.data)
        ]

    def _extract_log_and_annotations(self):
        """提取 Chromium 崩溃日志与 Crashpad 注解（key\\0value\\0 交替的 cstring 区）"""
        # 直接对原始字节匹配，避免拼接 blob 导致消息被 \x00 截断
        log_re = re.compile(
            rb"\[(\d+):(\d{4})/(\d{6})\.(\d+):(\w+):([^\]]{1,120})\]\s*([^\x00]{1,300})"
        )
        logs, seen_log = [], set()
        def build_raw():
            return "[{}:{}/{}.{}:{}:{}] {}".format(
                pid.decode(), md.decode(), hms.decode(), ms.decode(), lvl,
                loc.decode("ascii", "replace"), txt)

        for m in log_re.finditer(self.data):
            pid, md, hms, ms, level, loc, msg = m.groups()
            lvl = level.decode("ascii", "replace").upper()
            if lvl not in ("FATAL", "ERROR"):
                continue
            txt = msg.decode("ascii", "replace").strip()
            # 同一 location 只保留最长的一条（dump 中可能同时存在截断副本）
            key = (lvl, loc.decode("ascii", "replace"))
            if key in seen_log:
                prev = next(x for x in logs if (x["level"], x["location"]) == key)
                if len(txt) > len(prev["message"]):
                    prev["message"] = txt
                    prev["raw"] = build_raw()
                continue
            seen_log.add(key)
            logs.append({"pid": pid.decode(), "level": lvl,
                         "location": loc.decode("ascii", "replace"),
                         "message": txt, "raw": build_raw()})
            if len(logs) >= 10:
                break
        self.result["fatal_logs"] = logs

        # 供模式匹配的文本（限制大小，避免大文件开销）
        fatal_blob = " ".join(l["raw"] for l in logs)
        self._log_blob = (fatal_blob + " " +
                          " ".join(s for _, s in self._strings[:20000]))[:200000]
        self.result["log_blob"] = self._log_blob

        self.result["annotations"] = self._parse_annotation_block()
        prod = {}
        for key in ("_productName", "_version", "prod", "ver", "plat", "platform",
                    "osarch", "ptype", "process_type", "pid"):
            if key in self.result["annotations"]:
                prod[key] = self.result["annotations"][key]
        self.result["product"] = prod
        self.result["process_type"] = prod.get("ptype") or prod.get("process_type") or "unknown"

    def _read_cstring(self, offset: int, maxlen: int = 256) -> str:
        """读取 null 结尾的 ASCII 字符串（注解区分隔符就是 \\0，值可能只有 1 个字符）"""
        end = offset
        limit = min(offset + maxlen, len(self.data))
        while end < limit and self.data[end] != 0:
            end += 1
        try:
            return self.data[offset:end].decode("ascii", "replace")
        except Exception:
            return ""

    def _parse_annotation_block(self) -> dict:
        """
        Crashpad 注解存储格式（跨 Electron/Crashpad 版本稳定）：
            指针表 -> [u32 长度][字符串字节][\\0 + 填充至 4 字节对齐]
        key 与 value 成对交替存放，所有字段在内存中首尾相连。

        解析策略（先定位、后走链）：
          1. 定位：扫描全文件，找出所有「前 4 字节恰好等于自身长度、且以 \\0 终止」
             的字段，得到 {长度字段偏移: 文本} 映射。该自洽性约束可滤除绝大多数噪声。
          2. 走链：字段按顺序首尾相连，沿 next = cur + 4 + len + 1 + pad 前进，
             依次交替作为 key / value。链在遇到空槽或非法字段时自然中断。
        此策略不依赖指针表位置，因此对不同版本、不同进程类型均适用。
        """
        n = len(self.data)
        fields: dict[int, str] = {}
        # 候选起点：前一字节非可打印、当前字节可打印（即字符串的起始）
        cand = re.compile(rb"[^\x20-\x7e][\x20-\x7e]")
        for m in cand.finditer(self.data):
            p = m.start() + 1
            if p < 4 or p + 6 >= n:
                continue
            L = _u32(self.data, p - 4)
            if L == 0 or L > 512 or p + L >= n:
                continue
            if self.data[p + L] != 0:          # 必须 null 终止
                continue
            raw = self.data[p: p + L]
            if not all(32 <= b <= 126 for b in raw):
                continue
            fields[p - 4] = raw.decode("ascii", "replace")

        if not fields:
            return {}

        ann: dict[str, str] = {}
        visited: set[int] = set()
        key_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
        for start in sorted(fields):
            if start in visited:
                continue
            cur, pending = start, None
            while cur in fields and cur not in visited:
                visited.add(cur)
                txt = fields[cur]
                slen = len(txt)
                if pending is None:
                    # key 位：必须是合规键名才继续；否则该链不是注解链，放弃
                    if not key_re.match(txt):
                        break
                    pending = txt
                else:
                    ann.setdefault(pending, txt)
                    pending = None
                pad = (4 - ((slen + 1) % 4)) % 4
                cur = cur + 4 + slen + 1 + pad
        # 剔除 value 恰好是另一个 key 的错位项（多为 value 被误认作 key）
        keys = set(ann)
        return {k: v for k, v in ann.items()
                if k in keys and not (v in keys and ann.get(v) is not None
                                      and k != "_productName" and k != "_version")}

    # ---------- 崩溃地址定位 ----------
    def _locate_crash_address(self):
        exc = self.result.get("exception", {})
        addr = exc.get("address")
        info = {"address": addr}
        if addr:
            pc = addr
            ctx = exc.get("context", {})
            # 优先使用上下文中的 PC（崩溃时精确指令地址）
            for k in ("rip", "eip", "pc"):
                if k in ctx and ctx[k]:
                    pc = ctx[k]
                    break
            info["pc"] = pc
            for m in self.modules:
                if m["base"] <= pc < m["end"]:
                    off = pc - m["base"]
                    info.update({
                        "module": m["name"],
                        "module_path": m["path"],
                        "module_base": f"0x{m['base']:016X}",
                        "offset": off,
                        "offset_hex": f"0x{off:X}",
                        "in_main_module": m is self.result.get("main_module"),
                    })
                    break
            else:
                info["module"] = "<未知模块（地址不在任何已加载模块范围内）>"
        self.result["crash_location"] = info

    # ---------- 栈回溯 ----------
    def _unwind_stack(self):
        frames = []
        t = getattr(self, "crash_thread", None)
        if not t or not self.deep:
            self.result["stack"] = frames
            return
        ctx = self.result.get("exception", {}).get("context", {})
        sp = ctx.get("rsp") or ctx.get("esp") or ctx.get("sp")
        if not sp or not t["stack_start"]:
            self.result["stack"] = frames
            return
        off_in_stack = sp - t["stack_start"]
        if not (0 <= off_in_stack < t["stack_size"]):
            self.result["stack"] = frames
            return

        rva = t["stack_rva"] + off_in_stack
        limit = min(t["stack_size"] - off_in_stack, 0x8000)
        chunk = self.data[rva: rva + limit]

        for i in range(0, len(chunk) - 8, 8):
            if len(frames) >= self.max_stack:
                break
            val = struct.unpack_from("<Q", chunk, i)[0]
            # 排除明显非代码地址
            if val < 0x10000:
                continue
            for m in self.modules:
                if m["base"] <= val < m["end"]:
                    o = val - m["base"]
                    if o < 0x1000:  # 跳过模块头（非代码）
                        break
                    frames.append({
                        "offset_from_sp": i,
                        "address": f"0x{val:016X}",
                        "module": m["name"],
                        "module_offset": f"0x{o:X}",
                        "near_crash": abs(o - self.result["crash_location"].get("offset", -1)) < 0x100000,
                    })
                    break
        self.result["stack"] = frames

    # ---------- 诊断 ----------
    def _diagnose(self):
        c = {
            "exception_code": self.result.get("exception", {}).get("code"),
            "log_blob": getattr(self, "_log_blob", ""),
            "process_type": self.result.get("process_type", "unknown"),
        }
        matched = []
        for p in CRASH_PATTERNS:
            try:
                if p["test"](c):
                    matched.append({
                        "id": p["id"], "title": p["title"],
                        "severity": p["severity"], "detail": p["detail"],
                        "actions": p["actions"],
                    })
            except Exception:
                continue
        if not matched:
            matched.append({
                "id": "unknown",
                "title": "未匹配到已知崩溃模式",
                "severity": "P2",
                "detail": "请根据异常码与崩溃模块自行分析，或提供 PDB 符号以获得函数级调用栈。",
                "actions": ["加载 PDB 符号重新分析", "收集多个 dump 对比是否同一根因"],
            })

        # 导航重入专项提示
        ann = self.result.get("annotations", {})
        nav_keys = [k for k in ann if any(k.startswith(h) for h in NAV_HINT_KEYS)]
        nav_note = None
        if nav_keys:
            nav_note = {
                "keys": {k: ann[k] for k in nav_keys},
                "hint": ("检测到导航重入相关注解。典型诱因：在页面导航未完成（did-start-navigation 之后、"
                         "did-finish-load 之前）又发起了 reload()/loadURL()/location 跳转，"
                         "包括注入 JS 中的 location.reload()/location.href 赋值，或定时器自动刷新。"),
            }

        self.result["diagnosis"] = {
            "patterns": matched,
            "process_type": c["process_type"],
            "process_type_desc": PROCESS_TYPE_DESC.get(c["process_type"], "未知进程类型"),
            "navigation_reentrancy": nav_note,
        }


# ============================================================================
# metadata.bin 解析（Crashpad 崩溃历史）
# ============================================================================


class MetadataAnalyzer:
    """解析 Crashpad metadata.bin —— 崩溃报告索引"""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()

    def analyze(self) -> dict:
        d = self.data
        out = {"path": self.path, "size": len(d), "records": []}
        if len(d) < 16:
            return out

        magic = d[:4]
        out["magic"] = magic.decode("ascii", "replace")
        out["version"] = _u32(d, 4) if magic == b"DAPC" else None
        out["declared_count"] = _u32(d, 8) if magic == b"DAPC" else None

        # 1) 从尾部 ASCII 区提取 <uuid>.dmp 文件名（跨版本最可靠）
        text = d.decode("latin-1")
        uuids = re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text)
        out["dump_uuids"] = list(dict.fromkeys(uuids))

        # 2) 从二进制区按 GUID 混合字节序扫描记录 UUID（建立 guid -> offset 映射）
        bin_map: dict[str, int] = {}
        if magic == b"DAPC":
            for off in range(16, max(16, len(d) - 16)):
                g = format_guid(d[off: off + 16])
                if g == "00000000-0000-0000-0000-000000000000":
                    continue
                bin_map.setdefault(g, off)
        out["binary_uuids"] = [(v, k) for k, v in sorted(bin_map.items())[:10]]

        # 3) 时间戳：优先按「记录内固定偏移」读取（UUID 后 0x18 处通常为创建时间），
        #    避免在整文件盲扫时被 UUID 字节凑巧构成的数值误导。
        TS_MIN, TS_MAX = 1420070400, 2085974400   # 2015-01-01 ~ 2035-12-31

        def ts_in_record(off: int) -> int | None:
            for delta in (0x18, 0x14, 0x1C, 0x10, 0x20, 0x24):
                if off + delta + 4 <= len(d):
                    v = _u32(d, off + delta)
                    if TS_MIN <= v <= TS_MAX:
                        return v
            return None

        stamps = []
        for u in out["dump_uuids"]:
            off = bin_map.get(u)
            v = ts_in_record(off) if off is not None else None
            if v:
                stamps.append({"offset": off, "value": v, "time": fmt_ts(v)})
        out["timestamps"] = stamps

        # 4) 组装记录：UUID 与时间戳按记录一一对应
        for i, u in enumerate(out["dump_uuids"]):
            ts = next((s for s in stamps if s["offset"] == bin_map.get(u)), None)
            out["records"].append({
                "index": i, "uuid": u,
                "file": f"{u}.dmp",
                "timestamp": ts["time"] if ts else "N/A",
            })
        out["record_count"] = len(out["records"])
        out["note"] = ("UUID 取自文件尾部 ASCII 文件名区（可靠）；"
                       "时间戳为按记录结构启发式读取，仅供参考")
        return out


# ============================================================================
# 报告输出
# ============================================================================


def render_report(res: dict, meta: dict | None) -> str:
    L = []
    A = L.append
    bar = "=" * 78

    A(bar)
    A(" Electron / Chromium 崩溃转储分析报告")
    A(bar)
    A("")

    # ---- 1 文件 ----
    f = res["file"]
    A("【1】文件信息")
    A(f"  路径            : {f['path']}")
    A(f"  大小            : {f['size_human']} ({f['size']} 字节)")
    A(f"  签名 / 版本     : {f['signature']} / {f['version']}")
    A(f"  崩溃时间戳      : {Color.red(f['timestamp'])}")
    A(f"  Stream 数量     : {f['stream_count']}")
    A("")

    # ---- 2 应用与系统 ----
    A("【2】应用与运行环境")
    p = res.get("product", {})
    if p:
        A(f"  产品名称        : {p.get('_productName', 'N/A')}")
        A(f"  应用版本        : {p.get('_version', 'N/A')}")
        A(f"  框架            : {p.get('prod', 'N/A')} {p.get('ver', '')}")
        A(f"  进程类型        : {res.get('process_type', 'N/A')}")
    sysinfo = res.get("system", {})
    if sysinfo:
        A(f"  操作系统        : Windows {sysinfo.get('os_version')} {sysinfo.get('service_pack', '')}")
        A(f"  CPU             : {sysinfo.get('cpu_count')} 核 / {sysinfo.get('architecture')} ({sysinfo.get('bits')})")
        if sysinfo.get("cpu_vendor"):
            A(f"  CPU 厂商        : {sysinfo['cpu_vendor']}")
    proc = res.get("process", {})
    if proc:
        A(f"  进程 ID         : {proc.get('process_id', 'N/A')}")
        A(f"  进程启动        : {proc.get('process_created', 'N/A')}")
        if proc.get("uptime"):
            A(f"  崩溃前运行时长  : {Color.yellow(proc['uptime'])}")
        A(f"  CPU 时间        : 用户态 {proc.get('user_time_sec')}s / 内核态 {proc.get('kernel_time_sec')}s")
    mm = res.get("main_module", {})
    if mm:
        A(f"  主模块          : {mm.get('name')} ({human_size(mm.get('size', 0))}, 构建于 {mm.get('build_time')})")
        A(f"  主模块路径      : {mm.get('path')}")
    A("")

    # ---- 3 异常 ----
    A("【3】崩溃异常")
    e = res.get("exception", {})
    if e.get("present"):
        A(f"  异常代码        : {Color.red(e['code_hex'])}")
        A(f"  异常名称        : {Color.bold(e['name'])}")
        A(f"  含义            : {e['description']}")
        A(f"  崩溃线程 ID     : {e.get('thread_id')}")
        if e.get("access_type"):
            A(f"  访问类型        : {e['access_type']}")
        if e.get("fault_address"):
            A(f"  故障地址        : {e['fault_address']}")
        A(f"  不可继续        : {'是' if e.get('noncontinuable') else '否'}")
    else:
        A("  未发现 Exception Stream（可能是主动上报的非异常快照）")
    A("")

    # ---- 4 崩溃位置 ----
    A("【4】崩溃位置")
    cl = res.get("crash_location", {})
    A(f"  崩溃指令地址    : {Color.red('0x%016X' % cl.get('pc', 0)) if cl.get('pc') else 'N/A'}")
    A(f"  所属模块        : {cl.get('module', 'N/A')}")
    if cl.get("module_path"):
        A(f"  模块路径        : {cl['module_path']}")
        A(f"  模块基址        : {cl.get('module_base')}")
        A(f"  模块内偏移      : {cl.get('offset_hex')}")
        A(f"  是否主模块      : {'是（应用自身二进制 / Electron 内核）' if cl.get('in_main_module') else '否（第三方模块）'}")
    A("")

    # ---- 5 日志与注解 ----
    A("【5】崩溃日志")
    logs = res.get("fatal_logs", [])
    if logs:
        for lg in logs[:5]:
            A(f"  [{lg['level']}] {lg['location']}")
            A(f"      {Color.red(lg['message'][:200])}")
    else:
        A("  未提取到 FATAL/ERROR 级别日志（正式版可能省略详细日志）")
    A("")

    ann = res.get("annotations", {})
    if ann:
        A("【6】Crashpad 崩溃注解（关键上下文）")
        keys = [k for k in ann if any(k.startswith(h) for h in NAV_HINT_KEYS)]
        other = [k for k in ann if k not in keys]
        for k in sorted(keys):
            A(f"  {k:<45s} = {Color.yellow(ann[k])}")
        if other:
            A("  --- 其他 ---")
            for k in sorted(other)[:25]:
                A(f"  {k:<45s} = {ann[k]}")
        A("")

    # ---- 7 栈 ----
    st = res.get("stack", [])
    if st:
        A("【7】崩溃线程调用栈（候选帧，无符号表）")
        A("  说明：以下为栈内存中匹配到模块代码段的返回地址，需 PDB 符号才能解析函数名")
        A("")
        for fr in st[:30]:
            mark = "  <== 紧邻崩溃点" if fr["near_crash"] else ""
            A(f"    SP+0x{fr['offset_from_sp']:04X}  {fr['address']}  "
              f"{fr['module']}+{fr['module_offset']}{mark}")
        A("")

    # ---- 8 内存 ----
    mem = res.get("memory", {})
    if mem.get("present"):
        A("【8】内存概况（崩溃时进程地址空间）")
        A(f"  已提交内存      : {mem['commit_human']}")
        A(f"  保留内存        : {mem['reserve_human']}")
        A(f"  镜像(代码)提交  : {mem['image_commit_human']}")
        A(f"  内存区域数      : {mem['region_count']}")
        A("")

    # ---- 9 metadata ----
    if meta:
        A("【9】metadata.bin — 崩溃历史")
        A(f"  路径            : {meta['path']}")
        A(f"  格式 / 版本     : {meta.get('magic')} / v{meta.get('version')}")
        A(f"  声明记录数      : {meta.get('declared_count')}")
        A(f"  提取到 dump 数  : {Color.yellow(str(meta.get('record_count')))}")
        for r in meta.get("records", []):
            A(f"    [{r['index']}] {r['uuid']}  {r['timestamp']}")
        if meta.get("record_count", 0) > 1:
            A("")
            A("  " + Color.yellow("⚠ 存在多次崩溃记录，说明该问题是反复出现的稳定性缺陷，"))
            A("    建议收集全部 dump 对比是否为同一根因。")
        A("")

    # ---- 10 诊断 ----
    diag = res.get("diagnosis", {})
    A("【10】诊断结论")
    A(f"  崩溃进程类型    : {diag.get('process_type')} — {diag.get('process_type_desc')}")
    A("")
    for p in diag.get("patterns", []):
        A(f"  ● {Color.bold(p['title'])}   [{p['severity']}]")
        A(f"    {p['detail']}")
        A("")
    nav = diag.get("navigation_reentrancy")
    if nav:
        A("  " + Color.yellow("⚠ 导航重入专项提示"))
        for k, v in list(nav["keys"].items())[:12]:
            A(f"      {k:<45s} = {v}")
        A(f"    {nav['hint']}")
        A("")

    # ---- 11 建议 ----
    A("【11】修复建议")
    n = 1
    for p in diag.get("patterns", []):
        for a in p["actions"]:
            A(f"  {n}. {a}")
            n += 1
    if nav:
        A(f"  {n}. 在 reload()/loadURL() 前加入导航状态守卫（did-start-navigation 置位、")
        A(f"     did-finish-load / did-fail-load 复位），避免导航过程中重复触发导航")
        n += 1
        A(f"  {n}. 审查注入 JS：禁止在页面加载期调用 location.reload()/location.href 赋值")
        n += 1
        A(f"  {n}. 定时器自动刷新改为事件驱动 + 冷却时间，避免与用户操作叠加")
        n += 1
    A("")

    A(bar)
    A(" 说明：本报告为静态二进制解析结果。若需函数级调用栈，请在 Windows 上使用")
    A("       WinDbg/cdb 加载与主模块版本完全一致的 PDB 符号文件后执行:")
    A("         !analyze -v      （自动分析）")
    A("         kP               （打印带参数的调用栈）")
    A(bar)
    return "\n".join(L)


# ============================================================================
# 主流程
# ============================================================================


def find_metadata(dmp_path: str) -> str | None:
    """在 dump 同目录及父目录查找 metadata.bin"""
    d = os.path.dirname(os.path.abspath(dmp_path))
    for _ in range(3):
        cand = os.path.join(d, "metadata.bin")
        if os.path.isfile(cand):
            return cand
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def analyze_one(dmp: str, args) -> tuple[dict, dict | None, str]:
    an = MinidumpAnalyzer(dmp, max_stack=args.max_stack, deep=not args.quiet)
    res = an.analyze()
    meta = None
    if not args.quiet:
        mp = args.metadata or find_metadata(dmp)
        if mp and os.path.isfile(mp):
            try:
                meta = MetadataAnalyzer(mp).analyze()
            except Exception as ex:
                print(f"[warn] metadata.bin 解析失败: {ex}", file=sys.stderr)
    report = render_report(res, meta)
    return res, meta, report


def main():
    ap = argparse.ArgumentParser(
        description="通用 Electron / Chromium / CEF 崩溃转储分析器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python3 minidump_analyzer.py crash.dmp\n"
               "  python3 minidump_analyzer.py crash.dmp -o report.md\n"
               "  python3 minidump_analyzer.py ./crashes/ -j out.json\n",
    )
    ap.add_argument("target", help=".dmp 文件或包含 .dmp 的目录")
    ap.add_argument("-m", "--metadata", help="metadata.bin 路径（默认自动查找）")
    ap.add_argument("-o", "--output", help="输出报告到文件（Markdown/文本）")
    ap.add_argument("-j", "--json", dest="json_out", help="输出 JSON 结果")
    ap.add_argument("-q", "--quiet", action="store_true", help="精简输出（跳过字符串扫描）")
    ap.add_argument("--max-stack", type=int, default=40, help="栈回溯最大帧数（默认 40）")
    ap.add_argument("--no-color", action="store_true", help="禁用颜色")
    args = ap.parse_args()

    Color.enabled = not args.no_color

    # 收集目标文件
    if os.path.isdir(args.target):
        dmps = sorted(
            os.path.join(args.target, f)
            for f in os.listdir(args.target)
            if f.lower().endswith(".dmp")
        )
        if not dmps:
            print(f"[error] 目录中没有 .dmp 文件: {args.target}", file=sys.stderr)
            return 1
    elif os.path.isfile(args.target):
        dmps = [args.target]
    else:
        print(f"[error] 路径不存在: {args.target}", file=sys.stderr)
        return 1

    all_res = []
    reports = []
    for dmp in dmps:
        try:
            res, meta, rep = analyze_one(dmp, args)
            all_res.append({"dump": dmp, "result": res, "metadata": meta})
            reports.append(rep)
        except Exception as ex:
            print(f"[error] 分析失败 {dmp}: {ex}", file=sys.stderr)
            continue

    if not all_res:
        return 1

    full = "\n\n".join(reports)
    print(full)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(full)
        print(f"\n[ok] 报告已写入: {args.output}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(all_res, f, ensure_ascii=False, indent=2, default=str)
        print(f"[ok] JSON 已写入: {args.json_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
