# deepstack

> 公众号「栈深处」的文章配套资源库。
>
> 文章正文发在公众号，**这里放的是可以拿走复用的东西**：脚本、配图、脱敏样本、复现步骤。
>
> 兼容 Electron / Chromium / CEF / Go / 裸金属——凡是值得留下工具或数据的内容，都会在这里有一份。

---

## 一 · 目录规范

```
deepstack/
├── README.md              # 本文件：索引 + 规范
├── LICENSE                # 代码 MIT；文章文字内容不在本库，版权归作者
├── .gitignore
├── tools/                 # 跨文章可复用的工具（放这里，不放单篇目录下）
│   ├── README.md
│   └── <script>.py
└── articles/              # 每篇文章一个目录，命名 YYYY-MM-<slug>
    └── 2026-10-electron-crash/
        ├── README.md      # 本篇说明：问题、结论、复现步骤、关联文章
        ├── figures/       # 配图：SVG 源 + @2x PNG
        └── samples/       # 脱敏样本与输出示例
```

### 新增一篇文章

1. 建目录：`articles/YYYY-MM-<slug>/`，slug 用英文小写短横线（如 `bmc-ipmi-weirdness`）
2. 写 `README.md`：问题背景 → 结论 → 复现步骤 → 关联公众号文章
3. 配图放 `figures/`，**同时保留 SVG 源文件**（改起来方便，光有 PNG 下次得重画）
4. 样本放 `samples/`，**必须先脱敏**（见下）
5. 纯工具脚本放 `tools/`，只服务单篇的放本篇目录下
6. 回来更新本文件的索引表

### 样本脱敏（硬性）

上传前逐项检查，命中的一律替换：

| 类型 | 例子 | 处理 |
| --- | --- | --- |
| 真实用户名 / 家目录 | `C:\Users\张三\...`、`/Users/xxx/...` | `<user>` |
| 公司 / 产品 / 应用名 | `my-cool-app.exe` | `SomeApp.exe` |
| 内网 IP / 主机名 | `10.20.30.40` | `10.x.x.x` |
| 大体积二进制 | 30MB+ 的 dump、内存镜像 | **不入库**，改放解析后的输出示例 |
| 密钥 / token / cookie | — | 一律不入库 |

脱敏后跑一遍关键字扫描确认无残留，再 commit。

---

## 二 · 内容索引

| 目录 | 标题 | 类型 | 工具 |
| --- | --- | --- | --- |
| [`2026-10-electron-crash`](articles/2026-10-electron-crash/) | 没有符号表的时候，崩溃栈该怎么读 | 崩溃分析 | [`minidump_analyzer.py`](tools/minidump_analyzer.py) |

---

## 三 · 工具

| 脚本 | 用途 | 依赖 |
| --- | --- | --- |
| [`tools/minidump_analyzer.py`](tools/minidump_analyzer.py) | 解析 Windows minidump，提取崩溃日志、Crashpad 注解、崩溃历史。**不需要 Windows，不需要符号，不需要调试器** | 仅标准库 |

用法见 [`tools/README.md`](tools/README.md)。

---

## 四 · 关于文章原文

**文章原文不放在这个仓库。** 理由：原文只有一个事实源，放在本地内容库里，仓库只承担"可复用资产"的角色。

想看文章去公众号「栈深处」；想拿脚本和样本，留在这里。

---

## 五 · 许可证

代码（脚本、SVG 等）采用 MIT，见 [`LICENSE`](LICENSE)。

文章文字内容不在本库中，版权归作者所有，转载请联系。
