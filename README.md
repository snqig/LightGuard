<div align="center">

# LightGuard V2.0

### 终极完整版 - Windows 全能安全防护

超低资源 · 现代 Win11 UI · 原生防火墙 ACL · 全自动勒索防护 · 加密伪装备份 · 多语种 Unicode 兼容

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Win10%2FWin11%2FServer-0078D4)](https://learn.microsoft.com/windows/)
[![Arch](https://img.shields.io/badge/Arch-x64%2Farm64%2Fx86-orange)](https://learn.microsoft.com/dotnet/core/rid-catalog)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v1.0.1-blue)](https://github.com/snqig/LightGuard/releases)

</div>

---

## 目录

- [概述](#概述)
- [V1.0.1 安全加固](#v101-安全加固)
- [功能特性](#功能特性)
- [防火墙 ACL 模块](#防火墙-acl-模块)
- [勒索防护体系](#勒索防护体系)
- [更新安全机制](#更新安全机制)
- [系统要求](#系统要求)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [技术架构](#技术架构)
- [构建](#构建)
- [版本历史](#版本历史)
- [License](#license)

---

## 概述

LightGuard 是一款 Windows 桌面全能安全防护软件，采用模块化架构设计，集成了系统隐私加固、流氓软件净化、原生防火墙 ACL 管理、勒索病毒防护、加密智能备份和自动更新六大功能模块。单 EXE 绿色免安装，自包含 .NET 8 运行时，开箱即用。

### 核心亮点

| 特性 | 说明 |
|------|------|
| 单文件绿色版 | 自包含 .NET 8 运行时，无需安装依赖 |
| 双模式 UI | 高配 Mica 云母 + 圆角 / 低配极简，自动适配硬件 |
| 鼠标优先交互 | 所有配置通过下拉/复选/滑块/浏览弹窗完成，最小化键盘输入 |
| 多语种 Unicode | 支持简/繁中文、英文、越南语、印地语、阿拉伯语规则命名 |
| 智能后台调度 | 游戏全屏/低电量/前台操作自动暂停，Idle 优先级零干扰 |
| 零驱动安全 | 纯用户态实现，无内核驱动，无蓝屏风险 |
| 多架构支持 | x64 / ARM64 / x86 全架构构建，兼容 Server 2019/2022 |

---

## V1.0.1 安全加固

本次更新针对四项关键安全缺陷进行了深度修复：

### 1. 离线病毒库兜底

**问题**：勒索防护依赖规则库自动更新，断网环境下无本地离线病毒库兜底。

**修复**：新增 `OfflineVirusDb` 离线特征库引擎，内置 200+ 条勒索软件特征：

| 特征类别 | 数量 | 检测方式 |
|----------|------|----------|
| 加密后扩展名 | 120+ | `.wcry` `.locky` `.cerber` `.djvu` 等已知家族扩展名 |
| 勒索说明文件 | 30+ | `how_to_decrypt.txt` `README_RECOVER.txt` 等文件名模式 |
| 字节内容特征 | 30+ | WannaCry 标记、Bitcoin 地址模式、Tor Onion 链接 |
| 可疑进程名 | 40+ | `mssecsvc.exe` `tasksche.exe` 等已知勒索进程 |
| 系统进程白名单 | 40+ | `svchost.exe` `csrss.exe` 等核心进程永不被误判 |

断网环境下自动启用离线库，联网后合并在线特征库去重加载。

### 2. 进程行为沙箱隔离

**问题**：无进程行为沙箱隔离，仅靠防火墙 + 文件备份被动防护，无法主动阻断未知勒索程序。

**修复**：新增 `ProcessGuard` 进程行为沙箱引擎，实现主动防护：

| 能力 | 说明 |
|------|------|
| 进程启动监控 | WMI 事件监听 `Win32_ProcessStartTrace`，实时感知新进程 |
| 行为模式分析 | 批量文件操作检测（10秒内修改30+文件）、快速加密检测（3秒内修改同一文件3次） |
| 进程挂起隔离 | `NtSuspendProcess` 挂起可疑进程，不立即终止，保留取证现场 |
| 自动断网 | Critical 级别威胁触发防火墙全端口阻断 |
| 白名单保护 | 40+ 系统核心进程永不被隔离，避免误杀导致系统崩溃 |
| 降级容错 | WMI 不可用时自动降级为定时扫描模式 |

### 3. 更新包数字签名校验

**问题**：自动更新无校验机制，若更新服务器被劫持，可能下发恶意程序。

**修复**：新增 `UpdateSignatureVerifier` 数字签名校验引擎，双重验证：

| 校验层 | 算法 | 作用 |
|--------|------|------|
| 第一层 | SHA-256 | 文件完整性校验，确保下载内容未被篡改 |
| 第二层 | RSA-2048 + SHA-256 | 数字签名验证，确保更新包来自官方服务器 |

- 官方 RSA-2048 公钥嵌入程序内部，私钥仅由发布服务器保管
- 下载后自动校验 SHA-256 + RSA 签名，双重保险
- 应用更新前再次校验，防止本地文件被篡改
- 校验失败时拒绝应用更新并记录告警日志

### 4. 多架构与服务器系统支持

**问题**：仅支持 x64 Windows，不兼容 ARM、32 位系统、服务器系统。

**修复**：扩展 `HardwareDetector` 架构检测，支持全平台：

| 架构 | RID | 说明 |
|------|-----|------|
| x64 | `win-x64` | 64 位 Intel/AMD（主架构） |
| ARM64 | `win-arm64` | Snapdragon/Windows on ARM |
| x86 | `win-x86` | 32 位旧设备兼容 |

- 自动检测 `RuntimeInformation.ProcessArchitecture` 和 `OSArchitecture`
- 识别 Server 2019/2022（`Win32_OperatingSystem.ProductType`）
- GitHub Actions CD 工作流支持三架构矩阵构建
- 服务器系统自动适配 Win10/Win11 内核版本检测

---

## 功能特性

### 六大核心模块

| 模块 | 功能描述 |
|------|----------|
| **系统隐私加固** | 一键关闭遥测/广告/后台应用/搜索联网（12 项优化），家用/办公双模板 |
| **流氓软件净化** | WPS/360/Edge/2345 全套净化（20 项规则），全局防捆绑 + Hosts 广告屏蔽 |
| **防火墙管理** | 原生 COM 五元组 ACL 规则、批量目录 EXE 拦截、VPN 防绕过、4 套预设模板 |
| **勒索病毒防护** | 离线病毒库兜底 + 进程行为沙箱 + 多源病毒库聚合 + VSS 卷影副本秒还原 |
| **加密智能备份** | AES-256 加密 + .sys 伪装备份防勒索 + NTFS 增量 + NAS/WebDAV |
| **自动更新** | 三层更新 + RSA-2048 数字签名校验 + SHA-256 完整性验证 |

### 预设防护模板（一键应用）

| 模板 | 防护范围 |
|------|----------|
| Adobe 全家桶封锁 | 递归扫描 EXE + 全网卡 80/443 拦截 + VPN 阻断 + Hosts 劫持 + EXE 只读锁定 |
| 流氓软件更新拦截 | 阻断 WPS/360/Edge 更新服务器 + 全接口 VPN 绕过拦截 + Hosts 劫持 |
| 勒索高危端口防护 | 全局封禁 135/139/445/3389 入站流量（TCP + UDP） |
| 勒索应急断网 | 最高优先级，可疑进程全端口阻断所有网卡流量 + EXE 锁定 |

---

## 防火墙 ACL 模块

基于 Windows 原生 `INetFwPolicy2` COM 接口实现。

### 三大约束

1. **原生 COM 最优方案** — 零驱动、系统原生支持，兼容 Win10/Win11/Server，原生支持网卡接口筛选
2. **UI 鼠标优先** — 全下拉/复选/滑块/浏览弹窗，路径只读，端口地址快捷模板，仅备注可选输入
3. **Unicode 全语种兼容** — GUID 主键不依赖名称，UTF-16 内存 / UTF-8 BOM 导出，6 语种模板

### 规则管理能力

- **单程序精细化管控** — 三种网卡模式（全网卡/仅物理/仅 VPN）+ 三种端口策略
- **目录批量 EXE 拦截** — 递归扫描 + 勾选白名单 + 整组批量删除 + 失效规则自动清理
- **全局端口/IP 规则** — 高危端口封禁 + IP 黑名单 + 代理端口拦截
- **VPN 防绕过** — 虚拟网卡识别 + CIDR 网段提取 + 动态监听接口变更
- **导入导出** — JSON UTF-8 BOM 编码，多语言文本无损备份还原

---

## 勒索防护体系

V1.0.1 勒索防护升级为五层终极防护体系：

```
┌──────────────────────────────────────────────────┐
│  第五层：VSS 卷影副本（创建/还原/列出/清理）      │
├──────────────────────────────────────────────────┤
│  第四层：实时监控（高配）/ 闲置定时扫描（低配）    │
│          + 进程行为沙箱主动隔离                    │
├──────────────────────────────────────────────────┤
│  第三层：进程行为沙箱（ProcessGuard）              │
│          批量文件操作检测 + 进程挂起 + 自动断网     │
├──────────────────────────────────────────────────┤
│  第二层：智能双引擎扫描（特征匹配 + 行为启发）      │
├──────────────────────────────────────────────────┤
│  第一层：离线病毒库（200+条）+ 多源在线库聚合       │
│          ClamAV / Neo23x0 YARA / VirusTotal       │
└──────────────────────────────────────────────────┘
```

### 离线病毒库覆盖范围

- **WannaCry / WannaCry2** — `.wcry` `.wncry` `.wncryt` + 进程 `mssecsvc.exe` `tasksche.exe`
- **Locky / Cerber / GandCrab** — `.locky` `.cerber` `.gandcrab` + 字节特征匹配
- **CryptoLocker / CryptoWall** — `.encrypted` `.crypto` + 勒索说明文件检测
- **Djvu / STOP** — `.djvu` `.stop` `.rumba` + 30+ 变种扩展名
- **Conti / REvil / BlackCat** — 高危家族进程名 + 行为模式检测

---

## 更新安全机制

V1.0.1 更新模块新增双重安全校验：

| 阶段 | 校验内容 | 失败处理 |
|------|----------|----------|
| 下载完成 | SHA-256 完整性校验 | 删除文件，记录告警 |
| 下载完成 | RSA-2048 数字签名验证 | 拒绝存储，记录告警 |
| 应用前 | SHA-256 + RSA 二次校验 | 拒绝应用，记录告警 |

```
更新流程：
  获取清单 → 下载包 → SHA-256 校验 → RSA-2048 签名验证
                                              ↓ 通过
                                    应用差分更新 → 重启替换
                                              ↓ 失败
                                    拒绝更新 + 告警日志
```

---

## 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Windows 10 1903+ / Windows 11 / Server 2019 / Server 2022 |
| 架构 | x64 (Intel/AMD) / ARM64 (Snapdragon) / x86 (32位) |
| 权限 | 管理员权限（UAC 自动提权） |
| 磁盘 | ~70MB（单文件包含 .NET 运行时） |
| 内存 | 运行时约 20-30MB |

---

## 快速开始

1. 从 [Releases](https://github.com/snqig/LightGuard/releases) 下载对应架构的 `LightGuard.exe`
   - `LightGuard.exe` — x64 默认版
   - `LightGuard-v1.0.1-win-arm64.exe` — ARM64 设备
   - `LightGuard-v1.0.1-win-x86.exe` — 32 位系统
2. 右键 → **以管理员身份运行**
3. 首次启动跟随引导选择模式即可

> 单文件绿色版，无需安装，解压即用。配置存储在 `%APPDATA%\LightGuard\`。

---

## 项目结构

```
src/LightGuard/
├── Core/               # 核心框架
│   ├── Interfaces/     #   IModule 接口
│   ├── AppState.cs     #   全局状态单例
│   ├── ModuleBase.cs   #   模块基类
│   ├── ModuleManager.cs#   模块管理器
│   ├── HardwareDetector.cs  # 硬件检测 + 架构识别 + 服务器检测
│   └── ...             #   配置、调度、错误报告
├── Firewall/           # 防火墙 ACL 模块
│   ├── FirewallConst.cs        # 枚举常量、白名单、VPN 网段
│   ├── FirewallAclRule.cs      # 五元组规则实体（GUID + Unicode）
│   ├── FirewallAclManager.cs   # COM API 核心管理器
│   ├── AclPermissionHelper.cs  # NTFS 权限加固
│   ├── VpnNetworkTool.cs       # VPN 检测 + 代理读取
│   ├── FirewallPresets.cs      # 4 套预设模板
│   └── UnicodeTextHelper.cs    # 多语种文本处理
├── Ransomware/         # 勒索防护引擎（新增）
│   ├── OfflineVirusDb.cs       # 离线病毒库（200+ 特征）
│   └── ProcessGuard.cs         # 进程行为沙箱（主动隔离）
├── Security/           # 安全校验（新增）
│   └── UpdateSignatureVerifier.cs  # RSA-2048 数字签名验证
├── Native/             # Win32 API 封装
├── Modules/            # 六大功能模块实现
├── UI/                 # 界面层
│   ├── Pages/          #   8 个功能页面
│   ├── Controls/       #   自定义控件
│   ├── MainForm.cs     #   无边框主窗口
│   └── Theme.cs        #   双主题系统
├── Program.cs          # 入口
└── LightGuard.csproj   # 项目文件
```

---

## 技术架构

```
┌─────────────────────────────────────────────────────┐
│              UI 交互层 (WinForms)                    │
│   MainForm · 8 Pages · 鼠标优先 · 多语种             │
├─────────────────────────────────────────────────────┤
│           模块适配层 (IModule)                       │
│   Privacy · Cleanup · Firewall · Ransomware         │
│   Backup · Update                                   │
├─────────────────────────────────────────────────────┤
│           安全引擎层 (自研)                          │
│   离线病毒库 · 进程行为沙箱 · RSA 签名校验           │
│   VPN 识别 · NTFS/Hosts 联动 · 多语言模板            │
├─────────────────────────────────────────────────────┤
│           底层封装层 (COM P/Invoke)                  │
│   INetFwPolicy2 · DWM/Mica · VSS · 注册表            │
│   NtSuspendProcess · WMI · RSA/SHA256               │
└─────────────────────────────────────────────────────┘
```

### 技术栈

- **C# .NET 8** WinForms + P/Invoke
- **Windows Firewall COM API** (NetFwTypeLib / INetFwPolicy2)
- **NTFS ACL** 权限管理 (System.Security.AccessControl)
- **WMI** 进程监控 (ManagementEventWatcher)
- **RSA-2048 + SHA-256** 数字签名验证 (System.Security.Cryptography)
- **NtSuspendProcess** 进程挂起隔离 (ntdll.dll P/Invoke)
- **自定义 Fluent UI** 渲染引擎 (Mica / 圆角 / 双主题)
- **JSON** UTF-8 BOM 序列化 (多语言安全)

---

## 构建

```powershell
# 还原依赖
dotnet restore src/LightGuard/LightGuard.csproj

# 编译
dotnet build src/LightGuard/LightGuard.csproj -c Release

# 发布单文件 EXE — x64（默认）
dotnet publish src/LightGuard/LightGuard.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -o ./publish

# 发布单文件 EXE — ARM64
dotnet publish src/LightGuard/LightGuard.csproj `
  -c Release -r win-arm64 --self-contained true `
  -p:PublishSingleFile=true `
  -o ./publish-arm64

# 发布单文件 EXE — x86
dotnet publish src/LightGuard/LightGuard.csproj `
  -c Release -r win-x86 --self-contained true `
  -p:PublishSingleFile=true `
  -o ./publish-x86
```

> 需要 .NET SDK 8.0+ 或 10.0+

### CI/CD 自动构建

GitHub Actions 工作流 (`.github/workflows/cd-release.yml`) 支持：

- 三架构矩阵构建：`win-x64` / `win-arm64` / `win-x86`
- 自动发布到 GitHub Releases
- 每个架构生成独立 EXE + 统一 ZIP 包

---

## 版本历史

### v1.0.1 (2026-08-01)

**安全加固（四项关键缺陷修复）：**

- 新增离线病毒库引擎（`OfflineVirusDb`），内置 200+ 条勒索软件特征，断网环境完整防护
- 新增进程行为沙箱（`ProcessGuard`），主动监控批量文件操作 + 进程挂起隔离 + 自动断网
- 新增更新包数字签名校验（`UpdateSignatureVerifier`），RSA-2048 + SHA-256 双重验证
- 新增多架构支持：x64 / ARM64 / x86 全平台构建，兼容 Server 2019/2022

**防火墙 ACL 模块：**

- 原生 COM 五元组规则管理（INetFwPolicy2）
- VPN 防绕过：虚拟网卡识别 + CIDR 网段阻断 + 动态监听
- NTFS 权限加固：EXE 只读锁定 + 批量目录处理
- 4 套预设模板：Adobe 封锁 / 流氓拦截 / 勒索端口 / 应急断网
- 多语种 Unicode 兼容（6 语种模板：简/繁中、英、越、印地、阿拉伯）

**UI 改进：**

- UI 鼠标优先交互规范（全下拉/复选/滑块/浏览弹窗）
- JSON 导入导出 UTF-8 BOM 编码
- 修复页面导航不触发 OnShown 导致空白
- 修复模块启动时未初始化
- 修复窗口缩放内容不自适应

### v1.0.0 (2026-08-01)

- 初始版本发布
- 六大模块：隐私加固、流氓净化、防火墙、勒索防护、加密备份、自动更新
- 双模式 UI：Modern (Mica) / Minimal
- 智能后台调度
- 首次运行引导

---

## License

MIT License - 见 [LICENSE](LICENSE)

---

<div align="center">

**[下载最新版](https://github.com/snqig/LightGuard/releases)** · **[报告问题](https://github.com/snqig/LightGuard/issues)**

</div>
