<div align="center">

# 🛡 LightGuard V2.0

### 终极完整版 - Windows 全能安全防护

超低资源 · 现代 Win11 UI · 原生防火墙 ACL · 全自动勒索防护 · 加密伪装备份 · 多语种 Unicode 兼容

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Win10%2FWin11-0078D4)](https://learn.microsoft.com/windows/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Release](https://img.shields.io/badge/Release-v1.0.1-blue)](https://github.com/snqig/LightGuard/releases)

</div>

---

## 📋 目录

- [概述](#-概述)
- [功能特性](#-功能特性)
- [防火墙 ACL 模块](#-防火墙-acl-模块)
- [系统要求](#-系统要求)
- [快速开始](#-快速开始)
- [项目结构](#-项目结构)
- [技术架构](#-技术架构)
- [构建](#-构建)
- [版本历史](#-版本历史)
- [License](#-license)

---

## 🎯 概述

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

---

## ✨ 功能特性

### 六大核心模块

| 模块 | 功能描述 |
|------|----------|
| 🔒 **系统隐私加固** | 一键关闭遥测/广告/后台应用/搜索联网（12 项优化），家用/办公双模板 |
| 🧹 **流氓软件净化** | WPS/360/Edge/2345 全套净化（20 项规则），全局防捆绑 + Hosts 广告屏蔽 |
| 🌐 **防火墙管理** | 原生 COM 五元组 ACL 规则、批量目录 EXE 拦截、VPN 防绕过、4 套预设模板 |
| 🦠 **勒索病毒防护** | 多源病毒库聚合 + 双引擎扫描 + VSS 卷影副本秒还原 |
| 💾 **加密智能备份** | AES-256 加密 + .sys 伪装备份防勒索 + NTFS 增量 + NAS/WebDAV |
| 🔄 **自动更新** | 三层更新：软件本体 + 杀毒引擎 + 病毒库规则库 |

### 预设防护模板（一键应用）

| 模板 | 防护范围 |
|------|----------|
| Adobe 全家桶封锁 | 递归扫描 EXE + 全网卡 80/443 拦截 + VPN 阻断 + Hosts 劫持 + EXE 只读锁定 |
| 流氓软件更新拦截 | 阻断 WPS/360/Edge 更新服务器 + 全接口 VPN 绕过拦截 + Hosts 劫持 |
| 勒索高危端口防护 | 全局封禁 135/139/445/3389 入站流量（TCP + UDP） |
| 勒索应急断网 | 最高优先级，可疑进程全端口阻断所有网卡流量 + EXE 锁定 |

---

## 🔥 防火墙 ACL 模块

V1.0.1 新增完整防火墙 ACL 模块，基于 Windows 原生 `INetFwPolicy2` COM 接口实现。

### 三大约束

1. **原生 COM 最优方案** — 零驱动、系统原生支持，兼容 Win10/Win11，原生支持网卡接口筛选
2. **UI 鼠标优先** — 全下拉/复选/滑块/浏览弹窗，路径只读，端口地址快捷模板，仅备注可选输入
3. **Unicode 全语种兼容** — GUID 主键不依赖名称，UTF-16 内存 / UTF-8 BOM 导出，6 语种模板

### 规则管理能力

- **单程序精细化管控** — 三种网卡模式（全网卡/仅物理/仅 VPN）+ 三种端口策略
- **目录批量 EXE 拦截** — 递归扫描 + 勾选白名单 + 整组批量删除 + 失效规则自动清理
- **全局端口/IP 规则** — 高危端口封禁 + IP 黑名单 + 代理端口拦截
- **VPN 防绕过** — 虚拟网卡识别 + CIDR 网段提取 + 动态监听接口变更
- **导入导出** — JSON UTF-8 BOM 编码，多语言文本无损备份还原

---

## 💻 系统要求

- Windows 10 1903+ / Windows 11 x64
- 管理员权限（UAC 自动提权）
- ~70MB 磁盘空间（单文件包含运行时）

---

## 🚀 快速开始

1. 从 [Releases](https://github.com/snqig/LightGuard/releases) 下载 `LightGuard.exe`
2. 右键 → **以管理员身份运行**
3. 首次启动跟随引导选择模式即可

> 单文件绿色版，无需安装，解压即用。配置存储在 `%APPDATA%\LightGuard\`。

---

## 📁 项目结构

```
src/LightGuard/
├── Core/               # 核心框架
│   ├── Interfaces/     #   IModule 接口
│   ├── AppState.cs     #   全局状态单例
│   ├── ModuleBase.cs   #   模块基类
│   ├── ModuleManager.cs#   模块管理器
│   └── ...             #   硬件检测、配置、调度、错误报告
├── Firewall/           # 防火墙 ACL 模块（新增）
│   ├── FirewallConst.cs        # 枚举常量、白名单、VPN 网段
│   ├── FirewallAclRule.cs      # 五元组规则实体（GUID + Unicode）
│   ├── FirewallAclManager.cs   # COM API 核心管理器
│   ├── AclPermissionHelper.cs  # NTFS 权限加固
│   ├── VpnNetworkTool.cs       # VPN 检测 + 代理读取
│   ├── FirewallPresets.cs      # 4 套预设模板
│   └── UnicodeTextHelper.cs    # 多语种文本处理
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

## 🏗 技术架构

```
┌─────────────────────────────────────────────┐
│              UI 交互层 (WinForms)            │
│   MainForm · 8 Pages · 鼠标优先 · 多语种     │
├─────────────────────────────────────────────┤
│           模块适配层 (IModule)               │
│   Privacy · Cleanup · Firewall · Ransomware │
│   Backup · Update                           │
├─────────────────────────────────────────────┤
│           业务扩展层 (自研)                  │
│   VPN 识别 · 分组标签 · NTFS/Hosts 联动     │
│   失效规则清理 · 多语言模板                  │
├─────────────────────────────────────────────┤
│           底层封装层 (COM P/Invoke)          │
│   INetFwPolicy2 · DWM/Mica · VSS · 注册表   │
└─────────────────────────────────────────────┘
```

### 技术栈

- **C# .NET 8** WinForms + P/Invoke
- **Windows Firewall COM API** (NetFwTypeLib / hnetcfg.dll)
- **NTFS ACL** 权限管理 (System.Security.AccessControl)
- **自定义 Fluent UI** 渲染引擎 (Mica / 圆角 / 双主题)
- **JSON** UTF-8 BOM 序列化 (多语言安全)

---

## 🔧 构建

```powershell
# 还原依赖
dotnet restore src/LightGuard/LightGuard.csproj

# 编译
dotnet build src/LightGuard/LightGuard.csproj -c Release

# 发布单文件 EXE（自包含运行时）
dotnet publish src/LightGuard/LightGuard.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -o ./publish
```

> 需要 .NET SDK 8.0+ 或 10.0+

---

## 📝 版本历史

### v1.0.1 (2026-08-01)

- ✅ 新增完整防火墙 ACL 模块（7 个核心文件，~3000 行代码）
- ✅ 原生 COM 五元组规则管理（INetFwPolicy2）
- ✅ VPN 防绕过：虚拟网卡识别 + CIDR 网段阻断 + 动态监听
- ✅ NTFS 权限加固：EXE 只读锁定 + 批量目录处理
- ✅ 4 套预设模板：Adobe 封锁 / 流氓拦截 / 勒索端口 / 应急断网
- ✅ 多语种 Unicode 兼容（6 语种模板：简/繁中、英、越、印地、阿拉伯）
- ✅ UI 鼠标优先交互规范（全下拉/复选/滑块/浏览弹窗）
- ✅ JSON 导入导出 UTF-8 BOM 编码
- ✅ 修复页面导航不触发 OnShown 导致空白
- ✅ 修复模块启动时未初始化
- ✅ 修复窗口缩放内容不自适应

### v1.0.0 (2026-08-01)

- 初始版本发布
- 六大模块：隐私加固、流氓净化、防火墙、勒索防护、加密备份、自动更新
- 双模式 UI：Modern (Mica) / Minimal
- 智能后台调度
- 首次运行引导

---

## 📄 License

MIT License - 见 [LICENSE](LICENSE)

---

<div align="center">

**[⬇ 下载最新版](https://github.com/snqig/LightGuard/releases)** · **[🐛 报告问题](https://github.com/snqig/LightGuard/issues)**

</div>
